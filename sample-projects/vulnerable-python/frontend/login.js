// frontend/login.js
// Client-side authentication and search module
function submitSearch() {
  const searchInput = document.getElementById('search-box').value;
  
  // Untrusted user input sent to backend API endpoint
  fetch(`/api/users/search?q=${encodeURIComponent(searchInput)}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + localStorage.getItem('token')
    }
  })
  .then(response => response.json())
  .then(data => {
    displayResults(data.results);
  })
  .catch(err => {
    console.error('Search request failed', err);
  });
}

function displayResults(users) {
  const container = document.getElementById('results-list');
  container.innerHTML = '';
  users.forEach(user => {
    const item = document.createElement('div');
    item.textContent = `${user.username} (${user.email})`;
    container.appendChild(item);
  });
}
