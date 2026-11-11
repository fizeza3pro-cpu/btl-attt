#!/usr/bin/env bash
# Dua lab-rulegen ve TRANG THAI BAN DAU de demo lai kich ban 9 (chay tren B: ~/lab/rulegen-reset.sh)
#   - thu hoi moi rule tu sinh dang chay (lab-rule revoke -> nap nong lai Suricata)
#   - xoa phieu de xuat va ket qua lan phan tich
#   - dat moc thoi gian: rulegen BO QUA du lieu tan cong cu hon moc nay (neu khong no se hoc lai ngay tu log cu)
set -u
sids=$(sudo /usr/local/sbin/lab-rule status | python3 -c 'import json,sys; print(" ".join(str(r["sid"]) for r in json.load(sys.stdin)["rules"]))')
for sid in $sids; do
  printf "thu hoi %s: " "$sid"
  sudo /usr/local/sbin/lab-rule revoke "$sid" | python3 -c 'import json,sys; print(json.load(sys.stdin)["msg"])'
done
sudo systemctl stop lab-rulegen
echo "[]" | sudo -u labresp tee /var/lib/lab-rulegen/proposals.json >/dev/null
date +%s | sudo -u labresp tee /var/lib/lab-rulegen/since >/dev/null
sudo rm -f /var/lib/lab-rulegen/last_run.json
sudo systemctl start lab-rulegen
echo "Xong: 0 rule tu sinh, 0 phieu; rulegen chi xet du lieu tu $(date +%H:%M:%S)."
sudo suricatasc -c ruleset-stats
