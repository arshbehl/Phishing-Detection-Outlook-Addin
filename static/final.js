// Function to extract email content, URLs, and attachments and send to Flask backend
function analyzeEmailContent() {
    Office.context.mailbox.item.body.getAsync(Office.CoercionType.Html, function (result) {
        if (result.status === Office.AsyncResultStatus.Succeeded) {
            const emailHtmlContent = result.value;
            const attachments = Office.context.mailbox.item.attachments;;
            
            // Prepare payload for backend request
            const payload = new FormData();
            payload.append('email_content', emailHtmlContent);
            for (let i = 0; i < attachments.length; i++) {
                const attachment = attachments[i];
                payload.append('attachments', attachment);
            }
            
            // Make POST request to Flask backend
            axios.post('http://127.0.0.1:5000/analyze-email', payload)
                .then(response => {
                    // Handle response from Flask backend
                    console.log('Analysis results:', response.data);
                    displayAnalysisResults(response.data);
                })
                .catch(error => {
                    console.error('Error analyzing email:', error);
                    displayError('An error occurred during analysis.');
                });
        } else {
            console.error('Failed to retrieve email content:', result.error);
            displayError('Failed to retrieve email content.');
        }
    });
}

// Function to display analysis results
function displayAnalysisResults(results) {
    const resultsContainer = document.getElementById('resultsContainer');

    // Clear existing content in results container
    resultsContainer.innerHTML = '';

    // Create elements to display analysis results
    const sentimentScoresElement = document.createElement('div');
    sentimentScoresElement.innerHTML = `<h3>Sentiment Scores:</h3>
                                        <p>Positive: ${results.sentiment_scores.positive}</p>
                                        <p>Negative: ${results.sentiment_scores.negative}</p>
                                        <p>Neutral: ${results.sentiment_scores.neutral}</p>
                                        <p>Compound: ${results.sentiment_scores.compound}</p>`;

    const phishingElement = document.createElement('div');
    phishingElement.innerHTML = `<h3>Phishing Detection:</h3>
                                  <p>Is Phishing Email: ${results.is_phishing_email ? 'Yes' : 'No'}</p>`;

    const urlResultsElement = document.createElement('div');
    urlResultsElement.innerHTML = '<h3>URL Analysis:</h3>';
    const urlList = document.createElement('ul');

    // Iterate through URL results
    for (const [url, data] of Object.entries(results.url_results)) {
        const listItem = document.createElement('li');
        listItem.innerHTML = `<b>URL:</b> ${url}<br>
                              <b>Domain Info:</b> ${data.domain_info}<br>
                              <b>IP Addresses:</b> ${data.ip_addresses.join(', ')}<br>
                              <b>Safe URL:</b> ${data.is_safe_url ? 'Yes' : 'No'}`;
        urlList.appendChild(listItem);
    }
    urlResultsElement.appendChild(urlList);

    // Append elements to results container
    resultsContainer.appendChild(sentimentScoresElement);
    resultsContainer.appendChild(phishingElement);
    resultsContainer.appendChild(urlResultsElement);


    const attachmentResults = results.attachment_results;
    console.log('Attachment Results:', attachmentResults);
    // Example: Iterate through attachment results and update UI accordingly
    attachmentResults.forEach(attachment => {
        console.log('Attachment Name:', attachment.name);
        console.log('Attachment Content Type:', attachment.content_type);
        console.log('Attachment Size:', attachment.size);
        // Example: Update UI with attachment details
    });
}


// Call analyzeEmailContent function when the add-in button is clicked
function onAnalyzeButtonClick() {
    analyzeEmailContent();
}

// Add event listener to button
document.getElementById('analyzeButton').addEventListener('click', onAnalyzeButtonClick);
