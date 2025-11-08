async function checkAuth() {
  try {
    const response = await fetch('/api/check-auth');
    const data = await response.json();
    
    if (!data.authenticated) {
      window.location.href = 'index.html';
    } else {
      if (window.updateUsername && data.user) {
        updateUsername(data.user.username);
      }
    }
  } catch (error) {
    console.error('Error checking auth:', error);
    window.location.href = 'index.html';
  }
}

async function logout() {
  try {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = 'index.html';
  } catch (error) {
    console.error('Error logging out:', error);
    alert('Gagal logout');
  }
}

checkAuth();
