# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872151");
  script_version("2023-06-21T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:23 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-12-16 06:03:15 +0100 (Fri, 16 Dec 2016)");
  script_cve_id("CVE-2016-5199", "CVE-2016-5200", "CVE-2016-5201", "CVE-2016-5202",
                "CVE-2016-9651", "CVE-2016-5208", "CVE-2016-5207", "CVE-2016-5206",
                "CVE-2016-5205", "CVE-2016-5204", "CVE-2016-5209", "CVE-2016-5203",
                "CVE-2016-5210", "CVE-2016-5212", "CVE-2016-5211", "CVE-2016-5213",
                "CVE-2016-5214", "CVE-2016-5216", "CVE-2016-5215", "CVE-2016-5217",
                "CVE-2016-5218", "CVE-2016-5219", "CVE-2016-5221", "CVE-2016-5220",
                "CVE-2016-5222", "CVE-2016-9650", "CVE-2016-5223", "CVE-2016-5226",
                "CVE-2016-5225", "CVE-2016-5224", "CVE-2016-9652");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-07 21:15:00 +0000 (Fri, 07 Feb 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2016-a815b7bf5d");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"chromium on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2016-a815b7bf5d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7LGZO2VOGJOZUUXNQITD6YMIUQ2L5GTU");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~55.0.2883.87~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
