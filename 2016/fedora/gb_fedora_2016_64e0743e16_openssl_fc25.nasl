# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871989");
  script_version("2023-06-21T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:23 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"creation_date", value:"2016-12-07 05:22:45 +0100 (Wed, 07 Dec 2016)");
  script_cve_id("CVE-2016-6304", "CVE-2016-6306", "CVE-2016-6302", "CVE-2016-2179", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2180", "CVE-2016-2178", "CVE-2016-2177", "CVE-2016-7052");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:18:00 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for openssl FEDORA-2016-64e0743e16");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"openssl on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2016-64e0743e16");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2ONMKRXW4KFCDRJCCNX5UY46VXWTWEBA");
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

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.2j~1.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
