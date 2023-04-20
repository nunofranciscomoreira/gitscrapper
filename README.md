# gitscrapper
Automation for gitleaks to use in large gitlab instances.

In the future it will suport github enterprise instances, but I don't have an instance to test. 

## How to

Generate a personal access token for the git instance

https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#create-a-personal-access-token

Edit gitscrapper.py and add GIT_ENPOINT and GIT_PRIVATE_TOKEN

```sh
sudo pip install python-gitlab
git clone https://github.com/nunofranciscomoreira/gitscrapper
git clone https://github.com/gitleaks/gitleaks
cp gitscrapper/gitscrapper.py gitleaks
cd gitleaks
mkdir repositories leaks_reports
python3 gitscrapper.py
```
