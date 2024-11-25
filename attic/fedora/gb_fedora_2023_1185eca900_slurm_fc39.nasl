# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884930");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2023-41915");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-13 14:32:00 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-04 01:16:51 +0000 (Wed, 04 Oct 2023)");
  script_name("Fedora: Security Advisory for slurm (FEDORA-2023-1185eca900)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-1185eca900");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IFKIY6SNC3KQNZMVROWMIW6DI5XPNKQX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm'
  package(s) announced via the FEDORA-2023-1185eca900 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Slurm is an open source, fault-tolerant, and highly scalable
cluster management and job scheduling system for Linux clusters.
Components include machine status, partition management,
job management, scheduling and accounting modules.");

  script_tag(name:"affected", value:"'slurm' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
