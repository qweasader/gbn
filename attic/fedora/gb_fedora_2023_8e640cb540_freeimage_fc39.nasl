# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885170");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2021-40266", "CVE-2020-24292", "CVE-2020-24293", "CVE-2020-24295", "CVE-2021-40263");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-28 17:25:00 +0000 (Mon, 28 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:53 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for freeimage (FEDORA-2023-8e640cb540)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-8e640cb540");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CHZUSGS5VC6TODKRTIN5J42KWWLNS72W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeimage'
  package(s) announced via the FEDORA-2023-8e640cb540 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeImage is a library for developers who would like to support popular
graphics image formats like PNG, BMP, JPEG, TIFF and others as needed by
today&#39, s multimedia applications.");

  script_tag(name:"affected", value:"'freeimage' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
