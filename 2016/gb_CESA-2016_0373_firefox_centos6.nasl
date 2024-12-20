# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882411");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-10 06:14:56 +0100 (Thu, 10 Mar 2016)");
  script_cve_id("CVE-2016-1952", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1958",
                "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1964",
                "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1973", "CVE-2016-1974",
                "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792",
                "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796",
                "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800",
                "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2016:0373 centos6");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.
XULRunner provides the XUL Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-1952, CVE-2016-1954, CVE-2016-1957, CVE-2016-1958,
CVE-2016-1960, CVE-2016-1961, CVE-2016-1962, CVE-2016-1973, CVE-2016-1974,
CVE-2016-1964, CVE-2016-1965, CVE-2016-1966)

Multiple security flaws were found in the graphite2 font library shipped
with Firefox. A web page containing malicious content could cause Firefox
to crash or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2016-1977, CVE-2016-2790, CVE-2016-2791,
CVE-2016-2792, CVE-2016-2793, CVE-2016-2794, CVE-2016-2795, CVE-2016-2796,
CVE-2016-2797, CVE-2016-2798, CVE-2016-2799, CVE-2016-2800, CVE-2016-2801,
CVE-2016-2802)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bob Clary, Christoph Diehl, Christian Holler, Andrew
McCreight, Daniel Holbert, Jesse Ruderman, Randell Jesup, Nicolas
Golubovic, Jose Martinez, Romina Santillan, Abdulrahman Alqabandi,
ca0nguyen, lokihardt, Dominique Hazael-Massieux, Nicolas Gregoire, Tsubasa
Iinuma, the Communications Electronics Security Group (UK) of the GCHQ,
Holger Fuhrmannek, Ronald Crane, and Tyson Smith as the original reporters
of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 38.7.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"affected", value:"firefox on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0373");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021724.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.7.0~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
