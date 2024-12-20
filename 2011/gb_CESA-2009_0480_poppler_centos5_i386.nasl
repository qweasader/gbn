# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015865.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880707");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0480");
  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-1187", "CVE-2009-1188");
  script_name("CentOS Update for poppler CESA-2009:0480 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"poppler on CentOS 5");
  script_tag(name:"insight", value:"Poppler is a Portable Document Format (PDF) rendering library, used by
  applications such as Evince.

  Multiple integer overflow flaws were found in poppler. An attacker could
  create a malicious PDF file that would cause applications that use poppler
  (such as Evince) to crash or, potentially, execute arbitrary code when
  opened. (CVE-2009-0147, CVE-2009-1179, CVE-2009-1187, CVE-2009-1188)

  Multiple buffer overflow flaws were found in poppler's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause applications
  that use poppler (such as Evince) to crash or, potentially, execute
  arbitrary code when opened. (CVE-2009-0146, CVE-2009-1182)

  Multiple flaws were found in poppler's JBIG2 decoder that could lead to the
  freeing of arbitrary memory. An attacker could create a malicious PDF file
  that would cause applications that use poppler (such as Evince) to crash
  or, potentially, execute arbitrary code when opened. (CVE-2009-0166,
  CVE-2009-1180)

  Multiple input validation flaws were found in poppler's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause applications
  that use poppler (such as Evince) to crash or, potentially, execute
  arbitrary code when opened. (CVE-2009-0800)

  Multiple denial of service flaws were found in poppler's JBIG2 decoder. An
  attacker could create a malicious PDF file that would cause applications
  that use poppler (such as Evince) to crash when opened. (CVE-2009-0799,
  CVE-2009-1181, CVE-2009-1183)

  Red Hat would like to thank Braden Thomas and Drew Yao of the Apple Product
  Security team, and Will Dormann of the CERT/CC for responsibly reporting
  these flaws.

  Users are advised to upgrade to these updated packages, which contain
  backported patches to resolve these issues.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.5.4~4.4.el5_3.9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.5.4~4.4.el5_3.9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.5.4~4.4.el5_3.9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
