# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818257");
  script_version("2024-06-13T05:05:46+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2021-04-02 03:05:31 +0000 (Fri, 02 Apr 2021)");
  script_name("Fedora: Security Advisory for linux-firmware (FEDORA-2021-87e26421fb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-87e26421fb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IKRHXYB2IBEAZN6YHVCOFNFEIIMK7JDP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware'
  package(s) announced via the FEDORA-2021-87e26421fb advisory.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This package includes firmware files required for some devices to
operate.");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 32.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);