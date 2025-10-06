function OnLoad(){

    const form = document.getElementById('setupForm');

    async function OnSubmit(e){

        e.preventDefault();

        const formData = new FormData(e.target);

        const details = {
          CN: formData.get('cn'),
          organization: formData.get('organization'),
          country: formData.get('country'),
          stateOrProvince: formData.get('state_or_province'),
          password: formData.get('password')
        };
        
        // Send without callback - fire and forget
        await chrome.runtime.sendMessage({ type: 'setupDetails', details });
        window.close();
    }

    form.addEventListener('submit', OnSubmit);
}


document.addEventListener('DOMContentLoaded', OnLoad);