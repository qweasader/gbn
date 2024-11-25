# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852183");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335",
                "CVE-2018-18336", "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339",
                "CVE-2018-18340", "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343",
                "CVE-2018-18344", "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347",
                "CVE-2018-18348", "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351",
                "CVE-2018-18352", "CVE-2018-18353", "CVE-2018-18354", "CVE-2018-18355",
                "CVE-2018-18356", "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-17 21:15:00 +0000 (Sat, 17 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-12-18 07:39:11 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2018:4142-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"openSUSE-SU", value:"2018:4142-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00040.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the openSUSE-SU-2018:4142-1 advisory.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.814568");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update to Chromium 71.0.3578.98 fixes the
  following issues:

  Security issues fixed (boo#1118529):

  - CVE-2018-17480: Out of bounds write in V8

  - CVE-2018-17481: Use after frees in PDFium

  - CVE-2018-18335: Heap buffer overflow in Skia

  - CVE-2018-18336: Use after free in PDFium

  - CVE-2018-18337: Use after free in Blink

  - CVE-2018-18338: Heap buffer overflow in Canvas

  - CVE-2018-18339: Use after free in WebAudio

  - CVE-2018-18340: Use after free in MediaRecorder

  - CVE-2018-18341: Heap buffer overflow in Blink

  - CVE-2018-18342: Out of bounds write in V8

  - CVE-2018-18343: Use after free in Skia

  - CVE-2018-18344: Inappropriate implementation in Extensions

  - Multiple issues in SQLite via WebSQL

  - CVE-2018-18345: Inappropriate implementation in Site Isolation

  - CVE-2018-18346: Incorrect security UI in Blink

  - CVE-2018-18347: Inappropriate implementation in Navigation

  - CVE-2018-18348: Inappropriate implementation in Omnibox

  - CVE-2018-18349: Insufficient policy enforcement in Blink

  - CVE-2018-18350: Insufficient policy enforcement in Blink

  - CVE-2018-18351: Insufficient policy enforcement in Navigation

  - CVE-2018-18352: Inappropriate implementation in Media

  - CVE-2018-18353: Inappropriate implementation in Network Authentication

  - CVE-2018-18354: Insufficient data validation in Shell Integration

  - CVE-2018-18355: Insufficient policy enforcement in URL Formatter

  - CVE-2018-18356: Use after free in Skia

  - CVE-2018-18357: Insufficient policy enforcement in URL Formatter

  - CVE-2018-18358: Insufficient policy enforcement in Proxy

  - CVE-2018-18359: Out of bounds read in V8

  - Inappropriate implementation in PDFium

  - Use after free in Extensions

  - Inappropriate implementation in Navigation

  - Insufficient policy enforcement in Navigation

  - Insufficient policy enforcement in URL Formatter

  - Various fixes from internal audits, fuzzing and other initiatives

  - CVE-2018-17481: Use after free in PDFium (boo#1119364)

  The following changes are included:

  - advertisements posing as error messages are now blocked

  - Automatic playing of content at page load mostly disabled

  - New JavaScript API for relative time display

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1557=1");

  script_tag(name:"affected", value:"Chromium on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in OID:1.3.6.1.4.1.25623.1.0.814568
