# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873977");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-01-06 00:00:45 +0100 (Sat, 06 Jan 2018)");
  script_cve_id("CVE-2017-15412", "CVE-2017-15422", "CVE-2017-15407", "CVE-2017-15408",
                "CVE-2017-15409", "CVE-2017-15410", "CVE-2017-15411", "CVE-2017-15413",
                "CVE-2017-15415", "CVE-2017-15416", "CVE-2017-15417", "CVE-2017-15418",
                "CVE-2017-15419", "CVE-2017-15420", "CVE-2017-15423", "CVE-2017-15424",
                "CVE-2017-15425", "CVE-2017-15426", "CVE-2017-15427", "CVE-2017-15429",
                "CVE-2017-15398", "CVE-2017-15399", "CVE-2017-15386", "CVE-2017-15387",
                "CVE-2017-15388", "CVE-2017-15389", "CVE-2017-15390", "CVE-2017-15391",
                "CVE-2017-15392", "CVE-2017-15393", "CVE-2017-15394", "CVE-2017-15395",
                "CVE-2017-5124", "CVE-2017-5125", "CVE-2017-5126", "CVE-2017-5127",
                "CVE-2017-5133", "CVE-2017-5131", "CVE-2017-5130", "CVE-2017-5132",
                "CVE-2017-5129", "CVE-2017-5128");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-07 19:22:00 +0000 (Wed, 07 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for chromium FEDORA-2017-ea44f172e3");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"chromium on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2017-ea44f172e3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TCX6RNONWP5H4F6S2D3GX2IVGKVND34L");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~63.0.3239.108~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
