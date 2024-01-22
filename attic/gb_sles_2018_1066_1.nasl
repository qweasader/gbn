# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1066.1");
  script_version("2024-01-17T05:05:30+0000");
  script_cve_id("CVE-2018-10195");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 17:32:00 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-01-17 05:05:30 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");

  script_name("SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2018:1066-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003955.html");

  script_tag(name:"summary", value:"The remote host is missing an update for 'rzsz'
  package(s) announced via the SUSE-SU-2018:1066-1 advisory.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"'rzsz' package(s) on SUSE Linux Enterprise Server 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# Deprecated as the package name/version contains a "~" which can't be handled by the NASL based
# package comparison code. Users should update to GVM 22.04 or later to receive Notus-based LSCs
# which can handle this case.
exit(66);
