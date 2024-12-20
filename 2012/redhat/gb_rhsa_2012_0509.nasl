# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-April/msg00016.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870606");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 10:33:13 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1143", "CVE-2011-1590", "CVE-2011-1957", "CVE-2011-1958",
                "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175", "CVE-2011-2597",
                "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042",
                "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-1595");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2012:0509-01");
  script_name("RedHat Update for wireshark RHSA-2012:0509-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"wireshark on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  Several flaws were found in Wireshark. If Wireshark read a malformed packet
  off a network or opened a malicious dump file, it could crash or, possibly,
  execute arbitrary code as the user running Wireshark. (CVE-2011-1590,
  CVE-2011-4102, CVE-2012-1595)

  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malicious dump file. (CVE-2011-1143, CVE-2011-1957, CVE-2011-1958,
  CVE-2011-1959, CVE-2011-2174, CVE-2011-2175, CVE-2011-2597, CVE-2011-2698,
  CVE-2012-0041, CVE-2012-0042, CVE-2012-0067, CVE-2012-0066)

  Users of Wireshark should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running instances of
  Wireshark must be restarted for the update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.15~2.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.2.15~2.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
