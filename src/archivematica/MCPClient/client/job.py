"""
A Job is MCPClient's representation of a unit of work to be
performed--corresponding to a Task on the MCPServer side.  Jobs are run in
batches by clientScript modules and populated with an exit code, standard out
and standard error information.
"""

import datetime
import logging
import sys
import traceback
from collections.abc import Generator
from collections.abc import Iterable
from collections.abc import Mapping
from contextlib import contextmanager
from logging.handlers import BufferingHandler
from typing import Any
from typing import Optional
from typing import TypeVar
from typing import Union

from django.conf import settings
from django.utils import timezone
from django.db import utils as db_utils

from archivematica.dashboard.main.models import Task

logger = logging.getLogger("archivematica.mcp.client.job")

SelfJob = TypeVar("SelfJob", bound="Job")
TaskData = dict[str, Union[int, Optional[datetime.datetime], str]]


class Job:
    def __init__(
        self,
        name: str,
        uuid: str,
        arguments: list[str],
        capture_output: bool = False,
    ) -> None:
        """
        Arguments:
            name: job type, e.g. `move_sip`.
            uuid: Unique id for this job
            arguments: list of command line argument strings, e.g ["param1", "--foo"]
        Keyword arguments:
            capture_output: Flag for determining if output should be sent back to MCPServer
        """
        self.name = name
        self.uuid = uuid
        self.args = [name] + arguments
        self.capture_output = capture_output
        self.int_code = 0
        self.status_code = ""
        self.output = ""
        self.error = ""

        self.start_time: Optional[datetime.datetime] = None
        self.end_time: Optional[datetime.datetime] = None

    @classmethod
    def bulk_set_start_times(cls, jobs: list[SelfJob]) -> None:
        """Bulk set the processing start time for a batch of jobs."""
        start_time = timezone.now()
        uuids = [job.uuid for job in jobs]
        Task.objects.filter(taskuuid__in=uuids).update(starttime=start_time)
        for job in jobs:
            job.start_time = start_time

    @classmethod
    def bulk_mark_failed(cls, jobs: list[SelfJob], message: str) -> None:
        uuids = [job.uuid for job in jobs]

        Task.objects.filter(taskuuid__in=uuids).update(
            stderror=str(message), exitcode=1, endtime=timezone.now()
        )
        for job in jobs:
            job.set_status(1, status_code=message)

    def log_results(self) -> None:
        logger.info(
            (
                "#<%s; exit=%s; code=%s uuid=%s\n"
                "=============== STDOUT ===============\n"
                "%s"
                "\n=============== END STDOUT ===============\n"
                "=============== STDERR ===============\n"
                "%s"
                "\n=============== END STDERR ===============\n"
                "\n>"
            ),
            self.name,
            self.get_exit_code(),
            self.status_code,
            self.uuid,
            self.get_stdout(),
            self.get_stderr(),
        )

    def update_task_status(self) -> None:
        """Updates the Task model after a job has been completed."""
        # Not all jobs set an exit code. They expect a default of 0,
        # so keep compatibility with that
        if self.int_code is None:
            self.set_status(0)
        self.end_time = timezone.now()

        kwargs: TaskData = {
            "exitcode": self.get_exit_code(),
            "endtime": self.end_time,
        }
        if settings.CAPTURE_CLIENT_SCRIPT_OUTPUT:
            kwargs.update(
                {
                    "stdout": self.get_stdout(),
                    "stderror": self.get_stderr(),
                }
            )
        try:
            Task.objects.filter(taskuuid=self.uuid).update(**kwargs)
        except db_utils.OperationalError as exc:
            # MySQL/MariaDB may reject 4-byte UTF-8 characters (emojis) if the
            # column/table charset is not utf8mb4. Attempt a best-effort
            # sanitization of stdout/stderror by removing characters that when
            # encoded in UTF-8 take more than 3 bytes (i.e., non-BMP characters),
            # which covers surrogate-pair representations on narrow builds.
            msg = str(exc)
            if "Incorrect string value" in msg or "1366" in msg:
                logger.warning(
                    "Task update failed due to incompatible characters in output; attempting to sanitize and retry"
                )

                def _sanitize(s: Optional[str]) -> Optional[str]:
                    if s is None:
                        return s
                    try:
                        # Keep only characters whose utf-8 encoding is <= 3 bytes
                        out_chars = []
                        for ch in s:
                            try:
                                if len(ch.encode("utf-8")) <= 3:
                                    out_chars.append(ch)
                            except Exception:
                                # If encoding fails for a character, skip it
                                continue
                        sanitized = "".join(out_chars)
                        # Replace any remaining ill-formed sequences just in case
                        return sanitized.encode("utf-8", "replace").decode("utf-8", "replace")
                    except Exception:
                        # As a last resort, coerce to str and replace errors
                        try:
                            return str(s).encode("utf-8", "replace").decode("utf-8", "replace")
                        except Exception:
                            return None

                # Important: the OperationalError may have left the DB connection
                # in a broken transaction state. Close all connections to ensure
                # a fresh connection is used for the retry attempts.
                try:
                    from django import db as django_db
                    django_db.connections.close_all()
                except Exception:
                    # If closing connections fails, continue and attempts below
                    # may still fail; we will handle that.
                    logger.debug("Failed to close DB connections before retry; continuing anyway")

                kwargs_sanitized = kwargs.copy()
                if "stdout" in kwargs_sanitized:
                    kwargs_sanitized["stdout"] = _sanitize(kwargs_sanitized.get("stdout"))
                if "stderror" in kwargs_sanitized:
                    kwargs_sanitized["stderror"] = _sanitize(kwargs_sanitized.get("stderror"))

                # Retry once with sanitized content using a fresh connection
                try:
                    Task.objects.filter(taskuuid=self.uuid).update(**kwargs_sanitized)
                    return
                except Exception:
                    # Second attempt failed; try one more fallback by removing
                    # the output fields entirely and updating again.
                    try:
                        # Close connections again before final fallback
                        try:
                            django_db.connections.close_all()
                        except Exception:
                            pass
                    except Exception:
                        pass

                    fallback = kwargs_sanitized.copy()
                    if "stdout" in fallback:
                        fallback["stdout"] = None
                    if "stderror" in fallback:
                        fallback["stderror"] = None
                    try:
                        Task.objects.filter(taskuuid=self.uuid).update(**fallback)
                        return
                    except Exception:
                        logger.exception("Failed to update Task status for failed job after sanitization and fallback")
                        raise
            else:
                raise

    def set_status(self, int_code: int, status_code: str = "success") -> None:
        if int_code:
            self.int_code = int(int_code)
        self.status_code = status_code

    def write_output(self, s: str) -> None:
        self.output += s

    def write_error(self, s: str) -> None:
        self.error += s

    def print_output(self, *args: Iterable[Any]) -> None:
        self.write_output(" ".join([str(x) for x in args]) + "\n")

    def print_error(self, *args: Iterable[Any]) -> None:
        self.write_error(" ".join([str(x) for x in args]) + "\n")

    def pyprint(self, *objects: Iterable[Any], **kwargs: Mapping[str, Any]) -> None:
        output_type = kwargs.get("file", sys.stdout)
        sep = kwargs.get("sep", " ")
        end = kwargs.get("end", "\n")
        msg = str(sep).join([str(x) for x in objects]) + str(end)

        if output_type is sys.stdout:
            self.write_output(msg)
        elif output_type is sys.stderr:
            self.write_error(msg)
        else:
            raise Exception("Unrecognised print file: " + str(output_type))

    def get_exit_code(self) -> int:
        return self.int_code

    def get_stdout(self) -> str:
        return self.output

    def get_stderr(self) -> str:
        return self.error

    @contextmanager
    def JobContext(
        self, logger: Optional[logging.Logger] = None
    ) -> Generator[None, None, None]:
        if logger:
            handler = JobLogHandler(100, self)
            handler.setLevel(logging.INFO)
            handler.setFormatter(logging.Formatter(fmt="%(message)s"))
            logger.addHandler(handler)

        try:
            yield
        except Exception as e:
            self.write_error(str(e))
            self.write_error(traceback.format_exc())
            self.set_status(1, status_code="error")
        finally:
            if logger:
                logger.removeHandler(handler)


class JobLogHandler(BufferingHandler):
    """
    A handler that buffers log messages, and writes them to Job output
    when the buffer is full.
    """

    def __init__(self, capacity: int, job: Job) -> None:
        super().__init__(capacity)

        self.job = job

    def flush(self) -> None:
        for record in self.buffer:
            message = record.getMessage()
            if record.levelno >= logging.ERROR:
                self.job.write_error(message)
            else:
                self.job.write_output(message)

        # Clear the buffer via super()
        super().flush()
