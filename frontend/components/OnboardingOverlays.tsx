"use client";

// next/dynamic with ssr: false cannot be called from a Server Component (the
// root layout is async / server-rendered). This thin client wrapper calls
// nextDynamic at the client boundary so the ssr:false constraint is satisfied,
// while still keeping the OnboardingWizard and OnboardingTour bundles out of
// the initial JS payload (they are interactive-only overlays, never needed for
// first render).
import dynamic from "next/dynamic";

const OnboardingTour = dynamic(
  () => import("./OnboardingTour").then((m) => m.OnboardingTour),
  { ssr: false },
);

const OnboardingWizard = dynamic(
  () => import("./OnboardingWizard").then((m) => m.OnboardingWizard),
  { ssr: false },
);

export function OnboardingOverlays() {
  return (
    <>
      <OnboardingTour />
      <OnboardingWizard />
    </>
  );
}
