# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872480");
  script_version("2023-06-28T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:21 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-03-14 05:52:35 +0100 (Tue, 14 Mar 2017)");
  script_cve_id("CVE-2016-9422", "CVE-2016-9423", "CVE-2016-9424", "CVE-2016-9425",
                "CVE-2016-9428", "CVE-2016-9426", "CVE-2016-9429", "CVE-2016-9430",
                "CVE-2016-9431", "CVE-2016-9432", "CVE-2016-9433", "CVE-2016-9434",
                "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438",
                "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442",
                "CVE-2016-9443", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624",
                "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628",
                "CVE-2016-9629", "CVE-2016-9631", "CVE-2016-9630", "CVE-2016-9632",
                "CVE-2016-9633");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for w3m FEDORA-2017-2e6b693937");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"w3m on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-2e6b693937");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YSOH6NVKCFJP4GSVXHBDWHLEJ24W6HWV");
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

  if ((res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3~30.git20170102.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}