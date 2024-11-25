# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016131.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880821");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:21:52 +0000 (Wed, 14 Feb 2024)");
  script_xref(name:"CESA", value:"2009:1432");
  script_cve_id("CVE-2009-2408", "CVE-2009-2409", "CVE-2009-2654", "CVE-2009-3072", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077");
  script_name("CentOS Update for seamonkey CESA-2009:1432 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"seamonkey on CentOS 3");
  script_tag(name:"insight", value:"SeaMonkey is an open source Web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  SeaMonkey. (CVE-2009-3072, CVE-2009-3075)

  A use-after-free flaw was found in SeaMonkey. An attacker could use this
  flaw to crash SeaMonkey or, potentially, execute arbitrary code with the
  privileges of the user running SeaMonkey. (CVE-2009-3077)

  Dan Kaminsky discovered flaws in the way browsers such as SeaMonkey handle
  NULL characters in a certificate. If an attacker is able to get a
  carefully-crafted certificate signed by a Certificate Authority trusted by
  SeaMonkey, the attacker could use the certificate during a
  man-in-the-middle attack and potentially confuse SeaMonkey into accepting
  it by mistake. (CVE-2009-2408)

  Descriptions in the dialogs when adding and removing PKCS #11 modules were
  not informative. An attacker able to trick a user into installing a
  malicious PKCS #11 module could use this flaw to install their own
  Certificate Authority certificates on a user's machine, making it possible
  to trick the user into believing they are viewing a trusted site or,
  potentially, execute arbitrary code with the privileges of the user running
  SeaMonkey. (CVE-2009-3076)

  A flaw was found in the way SeaMonkey displays the address bar when
  window.open() is called in a certain way. An attacker could use this flaw
  to conceal a malicious URL, possibly tricking a user into believing they
  are viewing a trusted site. (CVE-2009-2654)

  Dan Kaminsky found that browsers still accept certificates with MD2 hash
  signatures, even though MD2 is no longer considered a cryptographically
  strong algorithm. This could make it easier for an attacker to create a
  malicious certificate that would be treated as trusted by a browser. NSS
  (provided by SeaMonkey) now disables the use of MD2 and MD4 algorithms
  inside signatures by default. (CVE-2009-2409)

  All SeaMonkey users should upgrade to these updated packages, which correct
  these issues. After installing the update, SeaMonkey must be restarted for
  the changes to take effect.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-chat", rpm:"seamonkey-chat~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-devel", rpm:"seamonkey-devel~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-js-debugger", rpm:"seamonkey-js-debugger~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-nspr", rpm:"seamonkey-nspr~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-nspr-devel", rpm:"seamonkey-nspr-devel~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-nss", rpm:"seamonkey-nss~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-nss-devel", rpm:"seamonkey-nss-devel~1.0.9~0.45.el3.centos3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
