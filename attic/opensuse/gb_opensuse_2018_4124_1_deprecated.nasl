# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852184");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-19968", "CVE-2018-19969", "CVE-2018-19970");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 14:10:00 +0000 (Mon, 22 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-12-18 07:40:27 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2018:4124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"openSUSE-SU", value:"2018:4124-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00032.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2018:4124-1 advisory.

  This VT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814560");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes security issues and bugs.

  Security issues addressed in the 4.8.4 release (bsc#1119245):

  - CVE-2018-19968: Local file inclusion through transformation feature

  - CVE-2018-19969: XSRF/CSRF vulnerability

  - CVE-2018-19970: XSS vulnerability in navigation tree

  This update also contains the following upstream bug fixes and
  improvements:

  - Ensure that database names with a dot ('.') are handled properly when
  DisableIS is true

  - Fix for message 'Error while copying database (pma__column_info)'

  - Move operation causes 'SELECT * FROM `undefined`' error

  - When logging with $cfg['AuthLog'] to syslog, successful login messages
  were not logged when $cfg['AuthLogSuccess'] was true

  - Multiple errors and regressions with Designer

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1547=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1547=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1547=1");

  script_tag(name:"affected", value:"phpMyAdmin on openSUSE Leap 42.3, openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in OID:1.3.6.1.4.1.25623.1.0.814560
