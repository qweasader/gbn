# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869464");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-06-25 06:31:41 +0200 (Thu, 25 Jun 2015)");
  script_cve_id("CVE-2015-3209", "CVE-2015-4163", "CVE-2015-4164", "CVE-2015-4103",
                "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-3456",
                "CVE-2015-3340", "CVE-2015-2752", "CVE-2015-2756", "CVE-2015-2751",
                "CVE-2015-2152", "CVE-2015-2151", "CVE-2015-2044", "CVE-2015-2045",
                "CVE-2015-0361", "CVE-2014-9065", "CVE-2014-8866", "CVE-2014-8867",
                "CVE-2014-9030", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-0150",
                "CVE-2014-7188", "CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156",
                "CVE-2014-5146", "CVE-2014-4021", "CVE-2014-3967", "CVE-2014-3968",
                "CVE-2014-3124", "CVE-2014-2599", "CVE-2013-2212", "CVE-2014-1950",
                "CVE-2014-1891", "CVE-2014-1892", "CVE-2014-1893", "CVE-2014-1894",
                "CVE-2014-1895", "CVE-2014-1896", "CVE-2014-1666", "CVE-2014-1642",
                "CVE-2013-6400", "CVE-2013-6885", "CVE-2013-4553", "CVE-2013-4554",
                "CVE-2013-6375");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for xen FEDORA-2015-9965");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"xen on Fedora 20");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-9965");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-June/160685.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC20");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.3.4~6.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
