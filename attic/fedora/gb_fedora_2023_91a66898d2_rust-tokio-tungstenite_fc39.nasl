# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884889");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2023-43669");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 15:42:00 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-10-01 01:18:17 +0000 (Sun, 01 Oct 2023)");
  script_name("Fedora: Security Advisory for rust-tokio-tungstenite (FEDORA-2023-91a66898d2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-91a66898d2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/64WBKNL6K5PXK6SXVGDZBZ5KAVTDHLQT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-tokio-tungstenite'
  package(s) announced via the FEDORA-2023-91a66898d2 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tokio binding for Tungstenite, the Lightweight stream-based WebSocket
implementation.");

  script_tag(name:"affected", value:"'rust-tokio-tungstenite' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
