package main

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/github"
	"github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
)

// TODO: configuration for full org scan, repo scan, or specific files.
// The latter case is useful for scanning PR's and gists.
// TODO: ignore git hashes. Solution: check git tree for commits with corresponding random string

// SensitivePos is the byte frame containing sensitive data. Start and End are
// starting and ending bytes of data.
type SensitivePos struct {
	Start, End int
}

// SensitiveFile is a file with one or more sensitive data.
type SensitiveFile struct {
	Path      string
	Positions []SensitivePos
}

// SensitiveRepo is a repo with one or more sensitive files.
type SensitiveRepo struct {
	Name  string
	Files []SensitiveFile
}

// Default name of the .credignore file. This file is formatted as a newline
// delimited list of files with paths relative to the repo directory. Each file
// in this list will not be checked for sensitive data.
const credIgnoreFile = ".credignore"

// CrawlOrg pulls all public GitHub repos owned by an org, then iteratively
// checks each repos' files for information appearing to be sensitive. A repo
// MAY have a '.credignore' file listing files with non-sensitive credentials
// that can be ignored.
func CrawlOrg(ctx context.Context, client *github.Client, orgName string) (srs []SensitiveRepo) {

	// Request all repos in org using GitHub API.
	opt := &github.RepositoryListByOrgOptions{Type: "public"}
	repos, _, err := client.Repositories.ListByOrg(ctx, orgName, opt)
	if err != nil {
		logrus.Error("CrawlOrg: ListByOrg: ", err)
		return nil
	}

	// Temp dir for repos
	cwd, err := os.Getwd()
	if err != nil {
		logrus.Error("CrawlOrg: Getwd: ", err)
		return nil
	}
	tmpDir, err := ioutil.TempDir(cwd, "tmp_")
	if err != nil {
		logrus.Error("CrawlOrg: TempDir: ", err)
		return nil
	}
	defer os.RemoveAll(tmpDir)
	// We are only concerned with paths relative to the tmp directory.
	tmpDir = filepath.Base(tmpDir)

	// Check for sensitive-looking data in each repo in repos.
	for _, repo := range repos {
		// Validate relevant API response fields
		if repo.Name == nil || *repo.Name == "" {
			continue
		}
		repoName := *repo.Name
		if repo.CloneURL == nil || *repo.CloneURL == "" {
			continue
		}

		// Clone the repo into our temp directory.
		repoDir := filepath.Join(tmpDir, repoName)
		_, err := git.PlainCloneContext(ctx, repoDir, false, &git.CloneOptions{
			URL:      *repo.CloneURL,
			Progress: os.Stdout,
		})
		if err != nil {
			logrus.Error("CrawlOrg: PlainCloneContext: ", err)
			continue
		}
		// Remove the .git directory, as we are not concerned with its files.
		gitDir := filepath.Join(tmpDir, repoName, ".git")
		if err = os.RemoveAll(gitDir); err != nil {
			logrus.Error("CrawlOrg: RemoveAll .git: ", err)
		}

		// Search for a top-level .credignore file. Parse contents if found.
		filesToIgnore := make(map[string]struct{})
		ignoreFile := filepath.Join(tmpDir, repoName, credIgnoreFile)
		if _, err := os.Stat(ignoreFile); err == nil {
			// Add our .credignore file so we don't check it
			filesToIgnore[filepath.Join(repoName, credIgnoreFile)] = struct{}{}

			if ignoreData, err := ioutil.ReadFile(ignoreFile); err == nil {
				logrus.Infof("Found %s file in repo '%s'.", credIgnoreFile, repoName)
				// .credignore files will list relevant files line-by-line, no
				// prefixes.
				ignoreList := strings.Split(string(ignoreData), "\n")
				for _, f := range ignoreList {
                    // Ignore newlines and comments, which start with '#'
                    if f != "" && f[0] != '#' {
                        filesToIgnore[f] = struct{}{}
                    }
				}
			}
		}

		// Now check each file in the repo, other than excluded files, for
		// sensitive content.
		sensitiveRepo := SensitiveRepo{
			Name: repoName,
		}
		f := func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}

            // Trim tmp directory and repo name from path.
            relPath, err := filepath.Rel(repoDir, path)
            if err != nil {
                logrus.Warnf("WalkFunc: found sensitive file '%s', rel path error: ", err)
                return nil
            }
			if _, ok := filesToIgnore[relPath]; ok {
				return nil
			}

			fileData, err := ioutil.ReadFile(path)
			if err != nil {
				logrus.Error("WalkFunc: ReadFile: ", err)
				return nil
			}

			// Does this file potentially have sensitive data? Append all
			// positions of sensitive data to this repos' list.
			if positions := HasSensitive(fileData); positions != nil {
				sensitiveRepo.Files = append(sensitiveRepo.Files, SensitiveFile{
					Path:      relPath,
					Positions: positions,
				})
			}

			return nil
		}
		if err := filepath.Walk(repoDir, f); err != nil {
			logrus.Error("CrawlOrg: Walk: ", err)
			continue
		}

		// If we found any sensitive data in this repo, add to our final set.
		if sensitiveRepo.Files != nil {
			srs = append(srs, sensitiveRepo)
		}
	}

	return
}

// HasSensitive searches fileData for any data resembling secret information,
// ex. random strings, and returns their byte positions in fileData.
func HasSensitive(fileData []byte) []SensitivePos {
	return nil
}
