# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853080");
  script_version("2022-08-05T10:11:37+0000");
  script_cve_id("CVE-2019-10214");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-05 10:11:37 +0000 (Fri, 05 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-25 16:15:00 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-26 04:01:42 +0000 (Thu, 26 Mar 2020)");
  script_name("openSUSE: Security Advisory for skopeo (openSUSE-SU-2020:0377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0377-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'skopeo'
  package(s) announced via the openSUSE-SU-2020:0377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for skopeo fixes the following issues:

  Update to skopeo v0.1.41 (bsc#1165715):

  - Bump github.com/containers/image/v5 from 5.2.0 to 5.2.1

  - Bump gopkg.in/yaml.v2 from 2.2.7 to 2.2.8

  - Bump github.com/containers/common from 0.0.7 to 0.1.4

  - Remove the reference to openshift/api

  - vendor github.com/containers/image/v5@v5.2.0

  - Manually update buildah to v1.13.1

  - add specific authfile options to copy (and sync) command.

  - Bump github.com/containers/buildah from 1.11.6 to 1.12.0

  - Add context to --encryption-key / --decryption-key processing failures

  - Bump github.com/containers/storage from 1.15.2 to 1.15.3

  - Bump github.com/containers/buildah from 1.11.5 to 1.11.6

  - remove direct reference on c/image/storage

  - Makefile: set GOBIN

  - Bump gopkg.in/yaml.v2 from 2.2.2 to 2.2.7

  - Bump github.com/containers/storage from 1.15.1 to 1.15.2

  - Introduce the sync command

  - openshift cluster: remove .docker directory on teardown

  - Bump github.com/containers/storage from 1.14.0 to 1.15.1

  - document installation via apk on alpine

  - Fix typos in doc for image encryption

  - Image encryption/decryption support in skopeo

  - make vendor-in-container

  - Bump github.com/containers/buildah from 1.11.4 to 1.11.5

  - Travis: use go v1.13

  - Use a Windows Nano Server image instead of Server Core for multi-arch
  testing

  - Increase test timeout to 15 minutes

  - Run the test-system container without --net=host

  - Mount /run/systemd/journal/socket into test-system containers

  - Don't unnecessarily filter out vendor from (go list ./...)
  output

  - Use -mod=vendor in (go {list, test, vet})

  - Bump github.com/containers/buildah from 1.8.4 to 1.11.4

  - Bump github.com/urfave/cli from 1.20.0 to 1.22.1

  - skopeo: drop support for ostree

  - Don't critically fail on a 403 when listing tags

  - Revert 'Temporarily work around auth.json location confusion'

  - Remove references to atomic

  - Remove references to storage.conf

  - Dockerfile: use golang-github-cpuguy83-go-md2man

  - bump version to v0.1.41-dev

  - systemtest: inspect container image different from current platform arch

  Changes in v0.1.40:

  - vendor containers/image v5.0.0

  - copy: add a --all/-a flag

  - System tests: various fixes

  - Temporarily work around auth.json location confusion

  - systemtest: copy: docker->storage->oci-archive

  - systemtest/010-inspect.bats: require only PATH

  - systemtest: add simple env test in inspect.bats

  - bash completion: add comments to keep scattered options in sync

  - bash completion: use read -r instead of disabling SC2207

  - bash completion: sup ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'skopeo' package(s) on openSUSE Leap 15.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~0.1.41~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~0.1.41~lp151.2.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);