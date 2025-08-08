// Wait for the DOM to be fully loaded
document.addEventListener('DOMContentLoaded', function() {
    // Get form elements
    const uploadForm = document.getElementById('uploadForm');
    const emailForm = document.getElementById('emailForm');
    
    // Get result sections
    const validationResults = document.getElementById('validationResults');
    const emailComposer = document.getElementById('emailComposer');
    const statusSection = document.getElementById('statusSection');
    const historySection = document.getElementById('historySection');
    
    // Get email list containers
    const validEmails = document.getElementById('validEmails');
    const invalidEmails = document.getElementById('invalidEmails');
    const validCount = document.getElementById('validCount');
    const invalidCount = document.getElementById('invalidCount');
    
    // Get status elements
    const statusMessage = document.getElementById('statusMessage');
    const progressBar = document.getElementById('progressBar');
    
    // Get history elements
    const historyTableBody = document.getElementById('historyTableBody');
    
    // Store valid emails for sending
    let validEmailsList = [];
    
    // Initialize animations
    initializeAnimations();

   // Handle file upload preview
    const attachmentInput = document.getElementById('attachments');
    const filePreviews = document.getElementById('filePreviews');

    if (attachmentInput && filePreviews) {
         attachmentInput.addEventListener('change', handleFileSelect);

    // Add drag and drop support
    const dropZone = document.querySelector('.file-upload-box');
    if (dropZone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, unhighlight, false);
        });

        dropZone.addEventListener('drop', handleDrop, false);
    }
}

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

function highlight() {
    document.querySelector('.file-upload-box').classList.add('highlight');
}

function unhighlight() {
    document.querySelector('.file-upload-box').classList.remove('highlight');
}

function handleDrop(e) {
    const dt = e.dataTransfer;
    const files = dt.files;

    attachmentInput.files = files; // Ensure FormData includes dropped files
    displaySelectedFiles(files);
}

function handleFileSelect(e) {
    displaySelectedFiles(this.files);
}

function displaySelectedFiles(files) {
    filePreviews.innerHTML = ''; // Clear old previews

    [...files].forEach(file => {
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
            showToast(`File ${file.name} is too large. Max size is 10MB.`, 'error');
            return;
        }

        const preview = createFilePreview(file);
        filePreviews.appendChild(preview);
    });
}

function createFilePreview(file) {
    const preview = document.createElement('div');
    preview.className = 'file-preview';
    preview.dataset.fileName = file.name;

    const fileIcon = document.createElement('i');
    fileIcon.className = getFileIconClass(file);

    const fileName = document.createElement('span');
    fileName.className = 'file-name';
    fileName.textContent = file.name;

    const removeBtn = document.createElement('span');
    removeBtn.className = 'remove-file';
    removeBtn.innerHTML = '&times;';
    removeBtn.onclick = () => preview.remove();

    preview.appendChild(fileIcon);
    preview.appendChild(fileName);
    preview.appendChild(removeBtn);

    return preview;
}

function getFileIconClass(file) {
    const fileType = file.type.split('/')[0];
    const fileExt = file.name.split('.').pop().toLowerCase();

    switch (fileType) {
        case 'image':
            return 'fas fa-file-image';
        case 'application':
            if (fileExt === 'pdf') return 'fas fa-file-pdf';
            if (['doc', 'docx'].includes(fileExt)) return 'fas fa-file-word';
            if (['xls', 'xlsx'].includes(fileExt)) return 'fas fa-file-excel';
            if (['ppt', 'pptx'].includes(fileExt)) return 'fas fa-file-powerpoint';
            if (['zip', 'rar', '7z'].includes(fileExt)) return 'fas fa-file-archive';
            return 'fas fa-file-alt';
        default:
            return 'fas fa-file';
    }
}

    // Check if we're on the home page with history section
    if (historySection) {
        // Load CSV upload history
        loadHistory();
    }
    
    // Function to handle file input change
    function setupFileInputChangeHandler() {
        const csvFileInput = document.getElementById('csvFile');
        if (csvFileInput) {
            // Update label immediately if a file is already selected (on page reload)
            if (csvFileInput.files.length > 0) {
                const fileName = csvFileInput.files[0].name;
                const fileLabel = csvFileInput.nextElementSibling;
                if (fileLabel) {
                    fileLabel.innerHTML = `<i class="fas fa-file-csv"></i> ${fileName}`;
                }
            }
            
            // Add change event listener
            csvFileInput.addEventListener('change', function() {
                const fileName = this.files[0] ? this.files[0].name : 'Choose CSV File';
                const fileLabel = this.nextElementSibling;
                if (fileLabel) {
                    fileLabel.innerHTML = `<i class="fas fa-file-csv"></i> ${fileName}`;
                }
                
                // Reset validation data
                validEmailsList = [];
                window.currentFileData = null;
                
                // Clear the UI
                if (validEmails) validEmails.innerHTML = '';
                if (invalidEmails) invalidEmails.innerHTML = '';
                if (validCount) validCount.textContent = '0';
                if (invalidCount) invalidCount.textContent = '0';
                
                // Hide the validation results and email composer
                if (validationResults) validationResults.classList.add('hidden');
                if (emailComposer) emailComposer.classList.add('hidden');
            });
        }
    }
    
    // Initialize file input change handler
    setupFileInputChangeHandler();
    
    // Handle file upload form submission
    if (uploadForm) {
        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get the file input
            const fileInput = document.getElementById('csvFile');
            const file = fileInput.files[0];
            
            if (!file) {
                showToast('Please select a CSV file', 'error');
                return;
            }
            
            // Create FormData object
            const formData = new FormData();
            formData.append('csvFile', file);
            
            // Show loading message
            statusSection.classList.remove('hidden');
            statusMessage.textContent = 'Uploading and validating emails...';
            progressBar.style.width = '50%';
            
            console.log('Sending email data:', Array.from(formData.entries()));
            
            // Send the file to the server
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                console.log('Response status:', response.status);
                console.log('Response headers:', response.headers);
                
                if (!response.ok) {
                    return response.text().then(text => {
                        console.log('Error response body:', text);
                        throw new Error('Network response was not ok: ' + response.status + ' ' + response.statusText + ' - ' + text);
                    });
                }
                return response.json();
            })
            .then(data => {
                // Update progress
                progressBar.style.width = '100%';
                
                console.log('Response data:', data);
                
                // Process the response data
                if (data.success) {
                    // Store file data for history update after sending
                    window.currentFileData = {
                        filename: data.filename,
                        original_filename: data.original_filename,
                        valid_count: data.valid_emails ? data.valid_emails.length : 0,
                        invalid_count: data.invalid_emails ? data.invalid_emails.length : 0
                    };
                    
                    // Clear and update the valid emails list
                    validEmailsList = Array.isArray(data.valid_emails) ? [...data.valid_emails] : [];
                    
                    // Clear the UI containers
                    validEmails.innerHTML = '';
                    invalidEmails.innerHTML = '';
                    
                    // Update the counts
                    validCount.textContent = validEmailsList.length;
                    invalidCount.textContent = data.invalid_emails ? data.invalid_emails.length : 0;
                    
                    // Function to add emails to a container with animation
                    const addEmailsToContainer = (emails, container) => {
                        if (!Array.isArray(emails)) return;
                        
                        emails.forEach((email, index) => {
                            if (!email) return;
                            
                            setTimeout(() => {
                                const div = document.createElement('div');
                                div.textContent = email;
                                div.style.opacity = '0';
                                container.appendChild(div);
                                
                                // Fade in animation
                                setTimeout(() => {
                                    div.style.transition = 'opacity 0.3s ease';
                                    div.style.opacity = '1';
                                }, 10);
                            }, index * 50); // Stagger the animations
                        });
                    };
                    
                    // Add emails to their respective containers
                    addEmailsToContainer(validEmailsList, validEmails);
                    if (Array.isArray(data.invalid_emails)) {
                        addEmailsToContainer(data.invalid_emails, invalidEmails);
                    }
                    
                    // Show the results section with animation
                    validationResults.style.opacity = '0';
                    validationResults.classList.remove('hidden');
                    setTimeout(() => {
                        validationResults.style.transition = 'opacity 0.5s ease';
                        validationResults.style.opacity = '1';
                    }, 10);
                    
                    // Show the email composer if there are valid emails
                    if (data.valid_emails.length > 0) {
                        emailComposer.style.opacity = '0';
                        emailComposer.classList.remove('hidden');
                        setTimeout(() => {
                            emailComposer.style.transition = 'opacity 0.5s ease';
                            emailComposer.style.opacity = '1';
                        }, 500);
                    } else {
                        emailComposer.classList.add('hidden');
                    }
                    
                    // Update status message
                    statusMessage.textContent = 'Email validation complete!';
                    showToast('Email validation complete!', 'success');
                    setTimeout(() => {
                        statusSection.classList.add('hidden');
                        progressBar.style.width = '0%';
                    }, 2000);
                } else {
                    // Show error message
                    statusMessage.textContent = 'Error: ' + data.message;
                    statusSection.classList.add('error');
                    showToast('Error: ' + data.message, 'error');
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                statusMessage.textContent = 'Error: ' + error.message;
                statusSection.classList.add('error');
                showToast('Error: ' + error.message, 'error');
            });
        });
    }
    
    // Handle email form submission
    if (emailForm) {
        emailForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Get form values
            const senderEmail = document.getElementById('senderEmail').value;
            const subject = document.getElementById('subject').value;
            const message = document.getElementById('message').value;
            const attachmentInput = document.getElementById('attachments');
            
            // Check required fields (subject/message only required if no attachments)
            if (!senderEmail || (!subject && !message && attachmentInput.files.length === 0)) {
                showToast('Please fill in required fields', 'error');
                return;
            }
            
            // Validate sender email
            const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!emailPattern.test(senderEmail)) {
                showToast('Please enter a valid email address', 'error');
                return;
            }
            
            // Create FormData for file uploads
            const formData = new FormData();
            formData.append('senderEmail', senderEmail);
            formData.append('subject', subject || '');
            formData.append('message', message || '');
            formData.append('emails', JSON.stringify(validEmailsList));
            
            // Add file attachments
            const files = attachmentInput.files;
            for (let i = 0; i < files.length; i++) {
                formData.append('attachments', files[i]);
            }
            
            // Add file information for history update
            if (window.currentFileData) {
                formData.append('filename', window.currentFileData.filename || '');
                formData.append('original_filename', window.currentFileData.original_filename || '');
                formData.append('valid_count', window.currentFileData.valid_count || 0);
                formData.append('invalid_count', window.currentFileData.invalid_count || 0);
            }
            
            // Show loading message
            statusSection.classList.remove('hidden');
            statusMessage.textContent = 'Sending emails...';
            progressBar.style.width = '50%';
            
            // Send the email data to the server
            fetch('/send', {
                method: 'POST',
                body: formData
            })
            .then(async response => {
                const contentType = response.headers.get('Content-Type') || '';
            
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Server error: ${response.status} ${response.statusText} - ${errorText}`);
                }
            
                if (!contentType.includes('application/json')) {
                    const raw = await response.text();
                    console.error('Non-JSON response:', raw);
                    throw new Error(`Expected JSON but got ${contentType}`);
                }
                
                console.log('Response URL:', response.url);
                return response.json();  // ✅ Only run if JSON is confirmed
                
            })
            .then(data => {
                progressBar.style.width = '100%';
            
                if (data.success) {
                    statusMessage.textContent = 'Emails sent successfully!';
                    showToast(`Sent ${data.successful_sends} emails successfully!`, 'success');
                    emailForm.reset();
                    loadHistory();
                    window.currentFileData = null;
                    setTimeout(() => {
                        emailComposer.style.opacity = '0';
                        setTimeout(() => {
                            emailComposer.classList.add('hidden');
                        }, 500);
                        statusSection.classList.add('hidden');
                        progressBar.style.width = '0%';
                    }, 3000);
                } else {
                    statusMessage.textContent = 'Error: ' + data.message;
                    statusSection.classList.add('error');
                    showToast('Error: ' + data.message, 'error');
                }
            })
            
            .catch(error => {
                console.error('Fetch Error:', error);
                statusMessage.textContent = 'Error: ' + error.message;
                statusSection.classList.add('error');
                showToast('Error: ' + error.message, 'error'); 
            });
        });
    }

    // Initialize animations and UI enhancements
    function initializeAnimations() {
        // Add toast container if it doesn't exist
        if (!document.getElementById('toast-container')) {
            const toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            document.body.appendChild(toastContainer);
        }
    }
    
    // Show toast notification
    function showToast(message, type = 'info') {
        const toastContainer = document.getElementById('toast-container');
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        let icon = 'info-circle';
        if (type === 'success') icon = 'check-circle';
        if (type === 'error') icon = 'exclamation-circle';
        
        toast.innerHTML = `<i class="fas fa-${icon}"></i> ${message}`;
        
        toastContainer.appendChild(toast);
        
        // Remove toast after animation completes
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }
    
    // Load CSV upload history
    function loadHistory() {
        fetch('/history')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to load history');
                }
                return response.json();
            })
            .then(data => {
                if (data.success && data.history) {
                    updateHistoryTable(data.history);
                } else {
                    console.error('Error loading history:', data.message);
                }
            })
            .catch(error => {
                console.error('Error loading history:', error);
            });
    }
    
    // Update history table with data
    function updateHistoryTable(history) {
        // Clear current history
        historyTableBody.innerHTML = '';
        
        if (history.length === 0) {
            // Show empty state
            const emptyRow = document.createElement('tr');
            emptyRow.className = 'empty-history';
            emptyRow.innerHTML = '<td colspan="6">No upload history yet</td>';
            historyTableBody.appendChild(emptyRow);
            return;
        }
        
        // Sort history by date (newest first)
        history.sort((a, b) => new Date(b.upload_date) - new Date(a.upload_date));
        
        // Add history entries to table
        history.forEach(entry => {
            const row = document.createElement('tr');
            
            row.innerHTML = `
                <td>${entry.original_filename}</td>
                <td>${entry.upload_date}</td>
                <td>${entry.valid_emails}</td>
                <td>${entry.invalid_emails}</td>
                <td>${entry.total_emails}</td>
                <td>${entry.sent_from || 'N/A'}</td>
            `;
            
            historyTableBody.appendChild(row);
        });
    }
});