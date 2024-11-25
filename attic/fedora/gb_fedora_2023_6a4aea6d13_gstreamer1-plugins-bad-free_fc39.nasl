# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885294");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2023-44429", "CVE-2023-44446");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"creation_date", value:"2023-11-19 02:16:47 +0000 (Sun, 19 Nov 2023)");
  script_name("Fedora: Security Advisory for gstreamer1-plugins-bad-free (FEDORA-2023-6a4aea6d13)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6a4aea6d13");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WCFFU4KXH7QTRSN5XDKHIOFOGCPHDSCZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1-plugins-bad-free'
  package(s) announced via the FEDORA-2023-6a4aea6d13 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer is a streaming media framework, based on graphs of elements which
operate on media data.

This package contains plug-ins that aren&#39, t tested well enough, or the code
is not of good enough quality.");

  script_tag(name:"affected", value:"'gstreamer1-plugins-bad-free' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
