# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.14399.1");
  script_cve_id("CVE-2017-9103", "CVE-2017-9104", "CVE-2017-9105", "CVE-2017-9106", "CVE-2017-9107", "CVE-2017-9108", "CVE-2017-9109");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:01 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-02 03:15:00 +0000 (Thu, 02 Jul 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:14399-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:14399-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-202014399-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'adns' package(s) announced via the SUSE-SU-2020:14399-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for adns fixes the following issues:

CVE-2017-9103,CVE-2017-9104,CVE-2017-9105,CVE-2017-9109: Fixed an issue
 in local recursive resolver which could have led to remote code
 execution (bsc#1172265).

CVE-2017-9106: Fixed an issue with upstream DNS data sources which could
 have led to denial of service (bsc#1172265).

CVE-2017-9107: Fixed an issue when quering domain names which could have
 led to denial of service (bsc#1172265).

CVE-2017-9108: Fixed an issue which could have led to denial of service
 (bsc#1172265).");

  script_tag(name:"affected", value:"'adns' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libadns1", rpm:"libadns1~1.4~75.3.1", rls:"SLES11.0SP4"))) {
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
