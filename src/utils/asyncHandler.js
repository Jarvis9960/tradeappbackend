export const asyncHandler = (handler) => async (req, res, next) => {
  try {
    await Promise.resolve(handler(req, res, next));
  } catch (error) {
    next(error);
  }
};