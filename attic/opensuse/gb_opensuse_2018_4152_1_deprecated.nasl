# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852187");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-10851", "CVE-2018-14626", "CVE-2018-14644", "CVE-2018-16855");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-12-18 07:41:17 +0100 (Tue, 18 Dec 2018)");
  script_name("openSUSE: Security Advisory for pdns-recursor (openSUSE-SU-2018:4152-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"openSUSE-SU", value:"2018:4152-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00046.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns-recursor'
  package(s) announced via the openSUSE-SU-2018:4152-1 advisory.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.814574");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pdns-recursor fixes the following issues:

  Security issues fixed:

  - CVE-2018-10851: Fixed denial of service via crafted zone record or
  crafted answer (bsc#1114157).

  - CVE-2018-14644: Fixed denial of service via crafted query for meta-types
  (bsc#1114170).

  - CVE-2018-14626: Fixed packet cache pollution via crafted query
  (bsc#1114169).

  - CVE-2018-16855: Fixed case where a crafted query could cause a denial of
  service (bsc#1116592)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1565=1");

  script_tag(name:"affected", value:"pdns-recursor on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in OID:1.3.6.1.4.1.25623.1.0.814574
