# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14846.1");
  script_cve_id("CVE-2021-20298", "CVE-2021-20300", "CVE-2021-20303", "CVE-2021-20304", "CVE-2021-3941");
  script_tag(name:"creation_date", value:"2021-12-02 03:22:29 +0000 (Thu, 02 Dec 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-26 16:10:19 +0000 (Fri, 26 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14846-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14846-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114846-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenEXR' package(s) announced via the SUSE-SU-2021:14846-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenEXR fixes the following issues:

CVE-2021-20298: Fixed out-of-memory in B44Compressor (bsc#1188460).

CVE-2021-20300: Fixed integer-overflow in Imf_2_5:hufUncompress
 (bsc#1188458).

CVE-2021-20303: Fixed heap-buffer-overflow in
 Imf_2_5::copyIntoFrameBuffe (bsc#1188457).

CVE-2021-20304: Fixed undefined-shift in Imf_2_5:hufDecode (bsc#1188461).

CVE-2021-3941: Fixed divide-by-zero in Imf_3_1:RGBtoXYZ (bsc#1192556).");

  script_tag(name:"affected", value:"'OpenEXR' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"OpenEXR", rpm:"OpenEXR~1.6.1~83.17.30.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenEXR-32bit", rpm:"OpenEXR-32bit~1.6.1~83.17.30.1", rls:"SLES11.0SP4"))) {
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
