# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807463");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-03-06 05:07:04 +0100 (Sun, 06 Mar 2016)");
  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4807", "CVE-2015-4815",
                "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830",
                "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870",
                "CVE-2015-4879", "CVE-2015-4895", "CVE-2015-4913", "CVE-2015-7744",
                "CVE-2016-0502", "CVE-2016-0503", "CVE-2016-0504", "CVE-2016-0505",
                "CVE-2016-0546", "CVE-2016-0594", "CVE-2016-0595", "CVE-2016-0596",
                "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0599", "CVE-2016-0600",
                "CVE-2016-0601", "CVE-2016-0605", "CVE-2016-0606", "CVE-2016-0607",
                "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0610", "CVE-2016-0611",
                "CVE-2016-0616");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 20:52:00 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mariadb FEDORA-2016-868");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"mariadb on Fedora 22");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2016-868");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-March/178514.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC22");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC22")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.0.23~1.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
