# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882185");
  script_version("2023-07-11T05:06:07+0000");
  script_cve_id("CVE-2015-1848");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-09 11:03:35 +0200 (Tue, 09 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for pcs CESA-2015:0990 centos6");
  script_tag(name:"summary", value:"Check the version of pcs");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The pcs packages provide a command-line
  tool and a web UI to configure and manage the Pacemaker and Corosync tools.

It was found that the pcs daemon did not sign cookies containing session
data that were sent to clients connecting via the pcsd web UI. A remote
attacker could use this flaw to forge cookies and bypass authorization
checks, possibly gaining elevated privileges in the pcsd web UI. Note: the
pcsd web UI is not enabled by default. (CVE-2015-1848)

This issue was discovered by Tomas Jelinek of Red Hat.

This update also fixes the following bug:

  * When the IPv6 protocol was disabled on a system, starting the pcsd daemon
on this system previously failed. This update adds the ability for pcsd to
fall back to IPv4 when IPv6 is not available. As a result, pcsd starts
properly and uses IPv4 if IPv6 is disabled. (BZ#1212115)

All pcs users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, the pcsd daemon will be restarted automatically.");
  script_tag(name:"affected", value:"pcs on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0990");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-May/021103.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"pcs", rpm:"pcs~0.9.123~9.0.1.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
