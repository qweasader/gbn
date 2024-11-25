# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886932");
  script_version("2024-09-05T12:18:35+0000");
  script_cve_id("CVE-2024-36048");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:35 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-06-07 06:34:35 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for qt5-qtspeech (FEDORA-2024-2e27372d4c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2e27372d4c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YE5V5R55Z6VCUJBISROXOIV4EK7AZQ3W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtspeech'
  package(s) announced via the FEDORA-2024-2e27372d4c advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The module enables a Qt application to support accessibility features such as
text-to-speech, which is useful for end-users who are
visually challenged or cannot access the application for whatever reason. The most common
use case where text-to-speech comes in handy
is when the end-user is driving and cannot attend the incoming messages on the phone. In
such a scenario, the messaging application
can read out the incoming message. Qt Serial Port provides the basic functionality, which
includes configuring, I/O operations,
getting and setting the control signals of the RS-232 pinouts.");

  script_tag(name:"affected", value:"'qt5-qtspeech' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
