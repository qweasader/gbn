# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886925");
  script_version("2024-09-05T12:18:35+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:35 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-06-07 06:34:34 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for rust-dotenvy (FEDORA-2024-40ee18b2e7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-40ee18b2e7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OGBYCWYAZ5JY22SYOOI3YOTU4ZRUDLT5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-dotenvy'
  package(s) announced via the FEDORA-2024-40ee18b2e7 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A well-maintained fork of the dotenv create.");

  script_tag(name:"affected", value:"'rust-dotenvy' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
