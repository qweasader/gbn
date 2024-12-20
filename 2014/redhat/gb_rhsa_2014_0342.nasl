# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871149");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-04-03 13:06:12 +0530 (Thu, 03 Apr 2014)");
  script_cve_id("CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6339",
                "CVE-2013-6340", "CVE-2013-7112", "CVE-2013-7114", "CVE-2014-2281",
                "CVE-2014-2283", "CVE-2014-2299");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for wireshark RHSA-2014:0342-01");


  script_tag(name:"affected", value:"wireshark on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Wireshark is a network protocol analyzer. It is used to capture and browse
the traffic running on a computer network.

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
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0342-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-March/msg00039.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.8.10~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.8.10~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.8.10~7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
