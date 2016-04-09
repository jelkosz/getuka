import unittest
import getuka


class TestParse(unittest.TestCase):

    def test_parse_bz_ids_from_gerrit_commit_empty(self):
        self.assertEqual('', ','.join(getuka.parse_bz_ids_from_gerrit_commit('')))

    def test_parse_bz_ids_from_gerrit_commit_one_end(self):
        msg = '''
frontend: Make boot menu enabled for run-once by default

Visually encourage users to not alter the boot order by itself but instead
select CDROM for run-once install via the BIOS boot menu (and optionally run in
paused mode) so after reboot - usually triggerred after installation the guest
will boot from hard drive and not the installation CDROM again.

Change-Id: I6a69857d4f987c9d2b82821591e529c2819bc3fa
Signed-off-by: Martin Betak <mbetak@redhat.com>
Bug-Url: https://bugzilla.redhat.com/show_bug.cgi?id=1054070'
        '''
        self.assertEqual('1054070', ','.join(getuka.parse_bz_ids_from_gerrit_commit(msg)))

    def test_parse_bz_ids_from_gerrit_commit_two_end(self):
        msg = '''
frontend: Make boot menu enabled for run-once by default

Visually encourage users to not alter the boot order by itself but instead
select CDROM for run-once install via the BIOS boot menu (and optionally run in
paused mode) so after reboot - usually triggerred after installation the guest
will boot from hard drive and not the installation CDROM again.

Change-Id: I6a69857d4f987c9d2b82821591e529c2819bc3fa
Signed-off-by: Martin Betak <mbetak@redhat.com>
Bug-Url: https://bugzilla.redhat.com/show_bug.cgi?id=1054070'
Bug-Url: https://bugzilla.redhat.com/1054070'
        '''
        self.assertEqual('1054070,1054070', ','.join(getuka.parse_bz_ids_from_gerrit_commit(msg)))

    def test_parse_bz_ids_from_gerrit_commit_two_middle(self):
        msg = '''
frontend: Make boot menu enabled for run-once by default

Visually encourage users to not alter the boot order by itself but instead
Bug-Url: https://bugzilla.redhat.com/show_bug.cgi?id=1054070'
select CDROM for run-once install via the BIOS boot menu (and optionally run in
paused mode) so after reboot - usually triggerred after installation the guest
Bug-Url: https://bugzilla.redhat.com/1054070'
will boot from hard drive and not the installation CDROM again.

Change-Id: I6a69857d4f987c9d2b82821591e529c2819bc3fa
Signed-off-by: Martin Betak <mbetak@redhat.com>
        '''
        self.assertEqual('1054070,1054070', ','.join(getuka.parse_bz_ids_from_gerrit_commit(msg)))

    def test_parse_change_id(self):
        msg = '''
frontend: Make boot menu enabled for run-once by default

Visually encourage users to not alter the boot order by itself but instead
Bug-Url: https://bugzilla.redhat.com/show_bug.cgi?id=1054070'
select CDROM for run-once install via the BIOS boot menu (and optionally run in
paused mode) so after reboot - usually triggerred after installation the guest
Bug-Url: https://bugzilla.redhat.com/1054070'
will boot from hard drive and not the installation CDROM again.

Change-Id: I6a69857d4f987c9d2b82821591e529c2819bc3fa
Signed-off-by: Martin Betak <mbetak@redhat.com>
        '''
        self.assertEqual('I6a69857d4f987c9d2b82821591e529c2819bc3fa', ','.join(getuka.parse_change_id_from_gerrit_commit(msg)))

if __name__ == '__main__':
    unittest.main()