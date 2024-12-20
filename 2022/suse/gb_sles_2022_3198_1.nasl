# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3198.1");
  script_cve_id("CVE-2021-32610");
  script_tag(name:"creation_date", value:"2022-09-09 04:51:43 +0000 (Fri, 09 Sep 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-06 20:47:14 +0000 (Fri, 06 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3198-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3198-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223198-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8-pear' package(s) announced via the SUSE-SU-2022:3198-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php8-pear fixes the following issues:

Add php8-pear to SLE15-SP4 (jsc#SLE-24728)

Update to 1.10.21
 - PEAR 1.10.13
 * unsupported protocol - use --force to continue
 * Add $this operator to _determineIfPowerpc calls

Update to 1.10.20
 - Archive_Tar 1.4.14
 * Properly fix symbolic link path traversal (CVE-2021-32610)
 - Archive_Tar 1.4.13
 * Relative symlinks failing (out-of path file extraction)
 - Archive_Tar 1.4.12
 - Archive_Tar 1.4.11
 - Archive_Tar 1.4.10
 * Fix block padding when the file buffer length is a multiple
 of 512 and smaller than Archive_Tar buffer length
 * Don't try to copy username/groupname in chroot jail

provides and obsoletes php7-pear-Archive_Tar, former location
 of PEAR/Archive/Tar.php

Update to version 1.10.19
 - PEAR 1.10.12
 * adjust dependencies based on new releases
 - XML_Util 1.4.5
 * fix Trying to access array offset on value of type int

Update to version 1.10.18

Remove pear-cacheid-array-check.patch (upstreamed)

Contents of .filemap are now sorted internally

Sort contents of .filemap to make build reproducible

Recommend php7-openssl to allow https sources to be used

Modify metadata_dir for system configuration only

Add /var/lib/pear directory where xml files are stored

Cleanup %files section

Only use the GPG keys of Chuck Burgess. Extracted from the Release
 Manager public keys.

Add release versions of PEAR modules

Install metadata files (registry, filemap, channels, ...) in
 /var/lib/pear/ instead of /usr/share/php7/PEAR/

Update to version 1.10.17");

  script_tag(name:"affected", value:"'php8-pear' package(s) on SUSE Linux Enterprise Module for Web Scripting 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"php8-pear", rpm:"php8-pear~1.10.21~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php8-pecl", rpm:"php8-pecl~1.10.21~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
