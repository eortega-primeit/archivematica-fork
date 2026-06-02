#!/usr/bin/env python
# This file is part of Archivematica.
#
# Copyright 2010-2013 Artefactual Systems Inc. <http://artefactual.com>
#
# Archivematica is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Archivematica is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Archivematica.  If not, see <http://www.gnu.org/licenses/>.
import json
import os
import re
import sys

import django

django.setup()
from django.db import transaction

from archivematica.dashboard.main.models import UnitVariable
from archivematica.MCPClient.clientScripts.verify_sip_compliance import checkDirectory

REQUIRED_DIRECTORIES = (
    "objects",
    "logs",
    "metadata",
    "metadata/submissionDocumentation",
)

ALLOWABLE_FILES = ("processingMCP.xml",)


def _get_ipds_re_preservation(unit_uuid):
    for unit_type in ("Transfer", "SIP"):
        try:
            unit_var = UnitVariable.objects.get(
                unittype=unit_type,
                unituuid=unit_uuid,
                variable="misc_attributes",
            )
            attrs = json.loads(unit_var.variablevalue or "{}")
            if attrs.get("ipds-re-preservation"):
                return True
        except UnitVariable.DoesNotExist:
            continue
    return False


def _get_uuid_from_path(sip_dir):
    """Extract the unit UUID from the transfer/SIP directory name.

    Directory names follow the pattern: <digits><Type>-<UUID>
    e.g. 333Transfer-23cfa0c5-5130-46d8-8bcb-d74e6e092b4b
    """
    basename = os.path.basename(sip_dir.rstrip("/"))
    m = re.search(
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
        basename,
        re.IGNORECASE,
    )
    return m.group(1) if m else None


def verifyDirectoriesExist(job, SIPDir, ret=0):
    for directory in REQUIRED_DIRECTORIES:
        if not os.path.isdir(os.path.join(SIPDir, directory)):
            job.pyprint(
                "Required Directory Does Not Exist: " + directory, file=sys.stderr
            )
            ret += 1
    return ret


def verifyNothingElseAtTopLevel(job, SIPDir, ret=0):
    for entry in os.listdir(SIPDir):
        if os.path.isdir(os.path.join(SIPDir, entry)):
            if entry not in REQUIRED_DIRECTORIES:
                job.pyprint("Error, directory exists: " + entry, file=sys.stderr)
                ret += 1
        else:
            if entry not in ALLOWABLE_FILES:
                job.pyprint("Error, file exists: " + entry, file=sys.stderr)
                ret += 1
    return ret


def verifyThereAreFiles(job, SIPDir, ret=0):
    """Make sure there are files in the transfer."""
    if not any(files for (_, _, files) in os.walk(SIPDir)):
        job.pyprint("Error, no files found", file=sys.stderr)
        ret += 1
    return ret


def call(jobs):
    with transaction.atomic():
        for job in jobs:
            with job.JobContext():
                SIPDir = job.args[1]
                sip_uuid = _get_uuid_from_path(SIPDir)

                if sip_uuid and _get_ipds_re_preservation(sip_uuid):
                    job.pyprint(
                        "ipds-re-preservation=True: skipping transfer compliance verification."
                    )
                    job.set_status(0)
                    continue

                ret = verifyDirectoriesExist(job, SIPDir)
                ret = verifyNothingElseAtTopLevel(job, SIPDir, ret)
                ret = checkDirectory(job, SIPDir, ret)
                ret = verifyThereAreFiles(job, SIPDir, ret)
                if ret != 0:
                    import time

                    time.sleep(10)
                job.set_status(ret)
