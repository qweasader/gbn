# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1775");
  script_cve_id("CVE-2014-3158", "CVE-2015-3310", "CVE-2020-8597");
  script_tag(name:"creation_date", value:"2020-07-03 06:25:27 +0000 (Fri, 03 Jul 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 19:15:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Huawei EulerOS: Security Advisory for ppp (EulerOS-SA-2020-1775)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1775");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1775");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ppp' package(s) announced via the EulerOS-SA-2020-1775 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in the getword function in options.c in pppd in Paul's PPP Package (ppp) before 2.4.7 allows attackers to 'access privileged options' via a long word in an options file, which triggers a heap-based buffer overflow that 'corrupts security-relevant variables.'(CVE-2014-3158)

Buffer overflow in the rc_mksid function in plugins/radius/util.c in Paul's PPP Package (ppp) 2.4.6 and earlier, when the PID for pppd is greater than 65535, allows remote attackers to cause a denial of service (crash) via a start accounting message to the RADIUS server.(CVE-2015-3310)

eap.c in pppd in ppp 2.4.2 through 2.4.8 has an rhostname buffer overflow in the eap_request and eap_response functions.(CVE-2020-8597)");

  script_tag(name:"affected", value:"'ppp' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"ppp", rpm:"ppp~2.4.5~33.h3.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.0"))) {
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
