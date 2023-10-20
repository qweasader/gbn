# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1259");
  script_cve_id("CVE-2017-14517", "CVE-2017-14518", "CVE-2017-14519", "CVE-2017-14520", "CVE-2017-14617", "CVE-2017-14929", "CVE-2017-14975", "CVE-2017-14976", "CVE-2017-14977", "CVE-2017-15565");
  script_tag(name:"creation_date", value:"2020-01-23 11:02:07 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-14 17:42:00 +0000 (Thu, 14 Mar 2019)");

  script_name("Huawei EulerOS: Security Advisory for poppler (EulerOS-SA-2017-1259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1259");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1259");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'poppler' package(s) announced via the EulerOS-SA-2017-1259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Poppler 0.59.0, a NULL Pointer Dereference exists in the XRef::parseEntry() function in XRef.cc via a crafted PDF document.(CVE-2017-14517)

In Poppler 0.59.0, a floating point exception exists in the isImageInterpolationRequired() function in Splash.cc via a crafted PDF document.(CVE-2017-14518)

In Poppler 0.59.0, memory corruption occurs in a call to Object::streamGetChar in Object.h after a repeating series of Gfx::display, Gfx::go, Gfx::execOp, Gfx::opShowText, and Gfx::doShowText calls (aka a Gfx.cc infinite loop).(CVE-2017-14519)

In Poppler 0.59.0, a floating point exception occurs in Splash::scaleImageYuXd() in Splash.cc, which may lead to a potential attack when handling malicious PDF files.(CVE-2017-14520)

In Poppler 0.59.0, a floating point exception occurs in the ImageStream class in Stream.cc, which may lead to a potential attack when handling malicious PDF files.(CVE-2017-14617)

In Poppler 0.59.0, memory corruption occurs in a call to Object::dictLookup() in Object.h after a repeating series of Gfx::display, Gfx::go, Gfx::execOp, Gfx::opFill, Gfx::doPatternFill, Gfx::doTilingPatternFill and Gfx::drawForm calls (aka a Gfx.cc infinite loop), a different vulnerability than CVE-2017-14519.(CVE-2017-14929)

The FoFiTrueType::getCFFBlock function in FoFiTrueType.cc in Poppler 0.59.0 has a NULL pointer dereference vulnerability due to lack of validation of a table pointer, which allows an attacker to launch a denial of service attack.(CVE-2017-14977)

The FoFiType1C::convertToType0 function in FoFiType1C.cc in Poppler 0.59.0 has a heap-based buffer over-read vulnerability if an out-of-bounds font dictionary index is encountered, which allows an attacker to launch a denial of service attack.(CVE-2017-14976)

The FoFiType1C::convertToType0 function in FoFiType1C.cc in Poppler 0.59.0 has a NULL pointer dereference vulnerability because a data structure is not initialized, which allows an attacker to launch a denial of service attack.(CVE-2017-14975)

In Poppler 0.59.0, a NULL Pointer Dereference exists in the GfxImageColorMap::getGrayLine() function in GfxState.cc via a crafted PDF document.(CVE-2017-15565)");

  script_tag(name:"affected", value:"'poppler' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.26.5~17.h10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~0.26.5~17.h10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt", rpm:"poppler-qt~0.26.5~17.h10", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.26.5~17.h10", rls:"EULEROS-2.0SP1"))) {
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
