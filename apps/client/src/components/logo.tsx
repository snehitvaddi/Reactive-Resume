import { useTheme } from "@reactive-resume/hooks";
import { cn } from "@reactive-resume/utils";

type Props = {
  size?: number;
  className?: string;
};

export const Logo = ({ size = 32, className }: Props) => {
  return (
    <img
      src="/logo/logo.png"
      width={size}
      height={size}
      alt="Finetune Resume"
      className={cn("rounded-sm", className)}
    />
  );
};
