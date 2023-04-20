#!/usr/bin/python3
"""List all Git projects and run gitleaks all
   Before running 
        create the "repositories" and "leaks_reports" folders
        change GIT_ENPOINT 
        change GIT_PRIVATE_TOKEN
"""
import subprocess
import os
from datetime import date
from multiprocessing.dummy import Pool as ThreadPool
import json
import gitlab


pwned_commands = []
clean_commands = []
today = date.today()
today_frmt = today.strftime("%b-%d-%Y")


def call_cmd(command_str):
    """Executes a command on the host machine."""
    try:
        subprocess.check_output(command_str, shell=True)
        if "gitleaks" in command_str:
            clean_commands.append(command_str)
    except BaseException:
        if "gitleaks" in command_str:
            pwned_commands.append(command_str)


def clone(ssh_url_to_repo, name):
    """Clones repository to the machine."""
    cmd = f"git clone {ssh_url_to_repo} repositories/{name}"
    call_cmd(cmd)


def gitleak_check(name, http_link):
    """Executes gitleak on a repository."""
    cmd = f"./gitleaks detect -s repositories/{name} --report-path leaks_reports/secrets_{name}.json"
    call_cmd(cmd)
    append_link(name, http_link)


def append_link(name, http_link):
    """Adds repository link to json report."""
    web = '{"RepoUrl": "'+  http_link + '\"},'
    try:
        with open(f"leaks_reports/secrets_{name}.json", "r+") as jsonFile:
            data_lines = jsonFile.read()
            if len(data_lines) <= 3:
                os.remove(f"leaks_reports/{name}.json")
            else:
                jsonFile.seek(0,0)
                a ='[\n '+ web+ '\n' + data_lines[2:]
                jsonFile.write(a)
    except:
        pass


def remove_repo(name):
    """Deletes Repository from the machine."""
    cmd = f"rm -rf repositories/{name}"
    call_cmd(cmd)


def organize(repos):
    """Schedules everything."""
    urls = repos.split("_")
    name = urls[0].split("/")
    ssh_url_to_repo = urls[0]
    repo_name_ssh = name[-1]
    repo_name_web = urls[1]
    clone(ssh_url_to_repo, repo_name_ssh)
    gitleak_check(repo_name_ssh, repo_name_web)
    remove_repo(repo_name_ssh)

if __name__ == "__main__":

    GIT_ENPOINT = "https://" # replace gitlab instance link
    GIT_PRIVATE_TOKEN = ""  # replace token

    gl = gitlab.Gitlab(url=GIT_ENPOINT, private_token=GIT_PRIVATE_TOKEN)
    gl.auth()
    git_projects = gl.projects.list(get_all=True)  # return all projects as a list, warning it will take time
    projects = []
    for project in git_projects:
        concatenated = project.ssh_url_to_repo + "_" + project.web_url
        projects.append(concatenated)

    pool = ThreadPool(os.cpu_count())  # only use the number of cores
    organizer = pool.map(organize, projects)
    pool.close()  # Close the pool
    pool.join()  # Wait for the work to finish
    
    with open(
        f"leaks_reports/{today_frmt}_pwned_commands.txt", "w", encoding="utf-8"
    ) as fp:
        for pwned_command in pwned_commands:
            fp.write(f"{pwned_command}\n")
    with open(
        f"leaks_reports/{today_frmt}_clean_commands.txt", "w", encoding="utf-8"
    ) as fp:
        for successful_command in clean_commands:
            fp.write(f"{successful_command}\n")

    print("Scan Done!")

    reports = os.listdir("leaks_reports/")
    for report in reports:
        if ".json" in report:
            try:
                fp = open(f"leaks_reports/{report}", "r", encoding="utf-8")
                file_content = json.load(fp)
                fp.close()
                if len(file_content) == 0:
                    os.remove(f"leaks_reports/{report}")
            except BaseException:
                pass
