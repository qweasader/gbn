# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881913");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-03 11:55:23 +0530 (Thu, 03 Apr 2014)");
  script_cve_id("CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6339",
                "CVE-2013-6340", "CVE-2013-7112", "CVE-2013-7114", "CVE-2014-2281",
                "CVE-2014-2283", "CVE-2014-2299");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for wireshark CESA-2014:0342 centos6");

  script_tag(name:"affected", value:"wireshark on CentOS 6");
  script_tag(name:"insight", value:"Wireshark is a network protocol analyzer. It is used to
capture and browse the traffic running on a computer network.

Two flaws were found in Wireshark. If Wireshark read a malformed packet off
a network or opened a malicious dump file, it could crash or, possibly,
execute arbitrary code as the user running Wireshark. (CVE-2014-2281,
CVE-2014-2299)

Several denial of service flaws were found in Wireshark. Wireshark could
crash or stop responding if it read a malformed packet off a network, or
opened a malicious dump file. (CVE-2013-6336, CVE-2013-6337, CVE-2013-6338,
CVE-2013-6339, CVE-2013-6340, CVE-2014-2283, CVE-2013-7112, CVE-2013-7114)

All Wireshark users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running instances
of Wireshark must be restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0342");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-March/020238.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~7.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.8.10~7.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.8.10~7.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
