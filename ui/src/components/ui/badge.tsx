import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

/**
 * Badge — small status pill.
 * Tuned for the nuon palette: subtle bordered fills, slightly tighter
 * text. `subtle` is the default "info" chip we use across cards.
 */
const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium leading-5 transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
  {
    variants: {
      variant: {
        default:     "border-transparent bg-primary text-primary-foreground",
        brand:       "border-transparent bg-brand-600 text-white",
        secondary:   "border-transparent bg-secondary text-secondary-foreground",
        subtle:      "border-border bg-accent text-accent-foreground",
        outline:     "text-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        success:     "border-transparent bg-emerald-600/95 text-white",
        warning:     "border-transparent bg-amber-500/95 text-white",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
