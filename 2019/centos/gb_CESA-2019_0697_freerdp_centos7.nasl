# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883032");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 16:29:00 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-04-13 02:00:40 +0000 (Sat, 13 Apr 2019)");
  script_name("CentOS Update for freerdp CESA-2019:0697 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0697");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-April/023267.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp'
  package(s) announced via the CESA-2019:0697 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP is a free implementation of the Remote Desktop Protocol (RDP),
released under the Apache license. The xfreerdp client can connect to RDP
servers such as Microsoft Windows machines, xrdp, and VirtualBox.

Security Fix(es):

  * freerdp: Integer truncation leading to heap-based buffer overflow in
update_read_bitmap_update() function (CVE-2018-8786)

  * freerdp: Integer overflow leading to heap-based buffer overflow in
gdi_Bitmap_Decompress() function (CVE-2018-8787)

  * freerdp: Out-of-bounds write in nsc_rle_decode() function (CVE-2018-8788)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'freerdp' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~1.0.2~15.el7_6.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~1.0.2~15.el7_6.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~1.0.2~15.el7_6.1", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-plugins", rpm:"freerdp-plugins~1.0.2~15.el7_6.1", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
