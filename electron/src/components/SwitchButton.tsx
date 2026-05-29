interface SwitchButtonProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}

export default function SwitchButton({ checked, onChange, disabled = false }: SwitchButtonProps) {
  const handleClick = () => {
    if (!disabled) {
      onChange(!checked);
    }
  };

  const classes = [
    'switch-track',
    checked ? 'on' : '',
    disabled ? 'disabled' : '',
  ].filter(Boolean).join(' ');

  return (
    <div
      className={classes}
      onClick={handleClick}
      role="switch"
      aria-checked={checked}
      tabIndex={disabled ? -1 : 0}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleClick();
        }
      }}
    >
      <span className="switch-indicator on-text">ON</span>
      <span className="switch-indicator off-text">OFF</span>
      <span className="switch-thumb" />
    </div>
  );
}
