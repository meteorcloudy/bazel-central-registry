import os
import sys
import requests

def dismiss_approvals(repo_full_name, pr_number, token):
    api_url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # Get all PR reviews
    response = requests.get(api_url, headers=headers)
    response.raise_for_status()  # Raises an exception for 4XX/5XX errors
    reviews = response.json()

    # Filter approved reviews
    approved_reviews = [review for review in reviews if review['state'] == 'APPROVED']

    # Dismiss each approved review
    for review in approved_reviews:
        review_id = review['id']
        dismiss_url = f"{api_url}/{review_id}/dismissals"
        payload = {"message": "New commits have been pushed. Please review again."}
        response = requests.put(dismiss_url, json=payload, headers=headers)
        try:
            response.raise_for_status()
            print(f"Successfully dismissed review {review_id}.")
        except requests.exceptions.HTTPError as e:
            print(f"Failed to dismiss review {review_id}: {e}")

if __name__ == "__main__":
    repo_full_name = sys.argv[1]  # 'owner/repo'
    pr_number = sys.argv[2]
    token = os.getenv('GITHUB_TOKEN')

    dismiss_approvals(repo_full_name, pr_number, token)
