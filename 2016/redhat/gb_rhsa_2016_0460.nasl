# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871578");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-03-17 05:09:13 +0100 (Thu, 17 Mar 2016)");
  script_cve_id("CVE-2016-1952", "CVE-2016-1954", "CVE-2016-1957", "CVE-2016-1960",
                "CVE-2016-1961", "CVE-2016-1964", "CVE-2016-1966", "CVE-2016-1974",
                "CVE-2016-1977", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792",
                "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796",
                "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800",
                "CVE-2016-2801", "CVE-2016-2802");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for thunderbird RHSA-2016:0460-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail
and newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2016-1952, CVE-2016-1954, CVE-2016-1957, CVE-2016-1960,
CVE-2016-1961, CVE-2016-1974, CVE-2016-1964, CVE-2016-1966)

Multiple security flaws were found in the graphite2 font library shipped
with Thunderbird. A web page containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2016-1977, CVE-2016-2790,
CVE-2016-2791, CVE-2016-2792, CVE-2016-2793, CVE-2016-2794, CVE-2016-2795,
CVE-2016-2796, CVE-2016-2797, CVE-2016-2798, CVE-2016-2799, CVE-2016-2800,
CVE-2016-2801, CVE-2016-2802)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bob Clary, Christoph Diehl, Christian Holler, Andrew
McCreight, Daniel Holbert, Jesse Ruderman, Randell Jesup, Nicolas
Golubovic, Jose Martinez, Romina Santillan, ca0nguyen, lokihardt, Nicolas
Grgoire, the Communications Electronics Security Group (UK) of the GCHQ,
Holger Fuhrmannek, Ronald Crane, and Tyson Smith as the original reporters
of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 38.7.0. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.7.0, which corrects these issues. After
installing the update, Thunderbird must be restarted for the changes to
take effect.");
  script_tag(name:"affected", value:"thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0460-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-March/msg00051.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~38.7.0~1.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~38.7.0~1.el6_7", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
