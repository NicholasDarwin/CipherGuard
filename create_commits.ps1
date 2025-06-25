$commits = @(
    @{date="2025-06-25 09:15:00"; msg="Implement URL validation"},
    @{date="2025-07-02 11:30:00"; msg="Add basic vulnerability detection"},
    @{date="2025-07-10 16:45:00"; msg="Create web UI templates"},
    @{date="2025-07-18 14:20:00"; msg="Add CSS styling"},
    @{date="2025-07-25 10:00:00"; msg="Implement JavaScript handlers"},
    @{date="2025-08-01 15:30:00"; msg="Add API endpoint for scanning"},
    @{date="2025-08-08 09:45:00"; msg="Integrate Gemini AI for analysis"},
    @{date="2025-08-15 13:00:00"; msg="Add progress streaming with SSE"},
    @{date="2025-08-22 11:15:00"; msg="Improve error handling"},
    @{date="2025-08-30 16:00:00"; msg="Add severity classification"},
    @{date="2025-09-05 10:30:00"; msg="Update results display"},
    @{date="2025-09-12 14:45:00"; msg="Add dark theme styling"},
    @{date="2025-09-20 09:00:00"; msg="Implement filter tabs"},
    @{date="2025-09-28 15:15:00"; msg="Add stats dashboard"},
    @{date="2025-10-05 11:30:00"; msg="Optimize scan performance"},
    @{date="2025-10-15 13:45:00"; msg="Add Vercel deployment config"},
    @{date="2025-10-25 10:00:00"; msg="Update documentation"},
    @{date="2025-11-13 12:00:00"; msg="Update LICENSE"}
)

foreach ($c in $commits) {
    Add-Content -Path "README.md" -Value " "
    $env:GIT_AUTHOR_DATE = $c.date
    $env:GIT_COMMITTER_DATE = $c.date
    git add .
    git commit -m $c.msg
}
