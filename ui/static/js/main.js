/**
 * EduGuard Auditor — Main Frontend Interactions
 */
document.addEventListener('DOMContentLoaded', () => {
    // Mobile Navigation Drawer Toggle
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const mobileNavMenu = document.getElementById('mobileNavMenu');
    
    if (mobileMenuBtn && mobileNavMenu) {
        mobileMenuBtn.addEventListener('click', () => {
            const isOpen = mobileNavMenu.classList.contains('open');
            if (isOpen) {
                mobileNavMenu.classList.remove('open');
                mobileMenuBtn.setAttribute('aria-expanded', 'false');
            } else {
                mobileNavMenu.classList.add('open');
                mobileMenuBtn.setAttribute('aria-expanded', 'true');
            }
        });

        // Close on link click
        mobileNavMenu.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                mobileNavMenu.classList.remove('open');
                mobileMenuBtn.setAttribute('aria-expanded', 'false');
            });
        });
    }

    // Preserve Model Selector in localStorage across routes
    const modelSelector = document.getElementById('aiModelSelector');
    if (modelSelector) {
        const savedModel = localStorage.getItem('eduguard_ai_model');
        if (savedModel && Array.from(modelSelector.options).some(o => o.value === savedModel)) {
            modelSelector.value = savedModel;
        }
        modelSelector.addEventListener('change', () => {
            localStorage.setItem('eduguard_ai_model', modelSelector.value);
        });
    }
});

/**
 * Toast Notification System for EduGuard
 */
window.EduToast = {
    container: null,
    activeToasts: {},

    ensureContainer() {
        if (!this.container) {
            this.container = document.getElementById('toast-container');
            if (!this.container) {
                this.container = document.createElement('div');
                this.container.id = 'toast-container';
                document.body.appendChild(this.container);
            }
        }
        return this.container;
    },

    show({ id, title, description, stage = 'loading', duration = 0 }) {
        this.ensureContainer();

        const toastId = id || `toast-${Date.now()}`;
        let el = this.activeToasts[toastId];

        const stageIcon = stage === 'success' 
            ? `<div class="w-7 h-7 rounded-full bg-[#E2FF32]/20 border border-[#E2FF32] flex items-center justify-center shrink-0 text-[#E2FF32]">
                 <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
               </div>`
            : (stage === 'error'
                ? `<div class="w-7 h-7 rounded-full bg-[#FF4D4D]/20 border border-[#FF4D4D] flex items-center justify-center shrink-0 text-[#FF4D4D]">
                     <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                   </div>`
                : `<div class="w-7 h-7 rounded-full bg-[#141414] border border-[#383838] flex items-center justify-center shrink-0">
                     <div class="w-3.5 h-3.5 border-2 border-neutral-600 border-t-[#E2FF32] rounded-full animate-spin"></div>
                   </div>`
            );

        const contentHtml = `
            <div class="flex items-start gap-3">
                ${stageIcon}
                <div class="flex-1 min-w-0">
                    <div class="flex items-center justify-between gap-2">
                        <h4 class="font-display font-medium text-sm text-white leading-tight">${title}</h4>
                        <button type="button" onclick="window.EduToast.dismiss('${toastId}')" class="text-neutral-500 hover:text-white transition-colors cursor-pointer text-xs">✕</button>
                    </div>
                    ${description ? `<p class="font-mono text-xs text-neutral-400 mt-1 leading-relaxed">${description}</p>` : ''}
                </div>
            </div>
        `;

        if (!el) {
            el = document.createElement('div');
            el.className = `toast-item font-mono text-xs toast-${stage}`;
            el.innerHTML = contentHtml;
            this.container.appendChild(el);
            this.activeToasts[toastId] = el;
            
            // Trigger animation frame
            requestAnimationFrame(() => {
                el.classList.add('toast-visible');
            });
        } else {
            el.className = `toast-item font-mono text-xs toast-visible toast-${stage}`;
            el.innerHTML = contentHtml;
        }

        if (duration > 0) {
            setTimeout(() => {
                this.dismiss(toastId);
            }, duration);
        }

        return toastId;
    },

    dismiss(id) {
        const el = this.activeToasts[id];
        if (el) {
            el.classList.remove('toast-visible');
            setTimeout(() => {
                if (el.parentNode) {
                    el.parentNode.removeChild(el);
                }
                delete this.activeToasts[id];
            }, 300);
        }
    }
};
