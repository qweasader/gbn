# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872282");
  script_version("2023-06-28T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-01-21 05:44:03 +0100 (Sat, 21 Jan 2017)");
  script_cve_id("CVE-2016-6836", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-8577",
                "CVE-2016-8578", "CVE-2016-8668", "CVE-2016-8669", "CVE-2016-8909",
                "CVE-2016-9101", "CVE-2016-9103", "CVE-2016-9102", "CVE-2016-9104",
                "CVE-2016-9105", "CVE-2016-9106", "CVE-2016-9381", "CVE-2016-9921",
                "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9846", "CVE-2016-9907",
                "CVE-2016-9911", "CVE-2016-9913", "CVE-2016-10028", "CVE-2016-9908",
                "CVE-2016-9912", "CVE-2016-9922", "CVE-2016-9914", "CVE-2016-9915",
                "CVE-2016-9916");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 16:29:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qemu FEDORA-2017-b953d4d3a4");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qemu on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-b953d4d3a4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3P2MMLAOGAYXF3BJW7266UZLPLFAXJRS");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC25");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.7.1~2.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
