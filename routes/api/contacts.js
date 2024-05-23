const express = require("express");
const contactsServices = require("../../controller/contactsController");
const router = express.Router();

const Joi = require("joi");
const schema = Joi.object({
  name: Joi.string().min(3).max(30).required(),
  email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ["com", "net", "ro"] } })
    .required(),
  phone: Joi.string().alphanum().min(10).max(20).required(),
  favorite: Joi.boolean(),
});

const favoriteSchema = Joi.object({ favorite: Joi.boolean() });

const STATUS_CODES = {
  success: 200,
  created: 201,
  deleted: 204,
  badRequest: 400,
  notFound: 404,
  error: 500,
};

/* GET localhost:3000/api/contacts */
router.get("/", async (req, res, next) => {
  try {
    const contactsList = await contactsServices.listContacts();
    res.status(STATUS_CODES.success).json({
      data: contactsList,
    });
  } catch (error) {
    respondWithError(res, error);
  }
});

/* GET localhost:3000/api/contacts/:contactId */
router.get("/:contactId", async (req, res, next) => {
  if (req.params.contactId.length !== 24) {
    res.status(STATUS_CODES.badRequest).json({
      message: "ID must have 24 alphanumeric characters",
    });
  } else {
    try {
      const contact = await contactsServices.getContactById(
        req.params.contactId
      );
      if (contact) {
        res.status(STATUS_CODES.success).json({
          data: contact,
        });
      } else {
        res.status(STATUS_CODES.notFound).json({
          message: "The contact was not found.",
        });
      }
    } catch (error) {
      respondWithError(res, error);
    }
  }
});

/* POST localhost:3000/api/contacts */
router.post("/", async (req, res, next) => {
  try {
    const { error, value } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      let errors = error.details;

      let message = "";
      for (i = 1; i <= errors.length; i++) {
        message += errors[i - 1].message;
        if (i < errors.length) message += ", ";
      }
      res.status(STATUS_CODES.badRequest).json({
        message: message,
      });
    } else {
      await contactsServices.addContact(req.body);
      res.status(STATUS_CODES.created).json({
        message: `The contact has been successfully added.`,
        data: req.body,
      });
    }
  } catch (error) {
    respondWithError(res, error);
  }
});

/* DELETE localhost:3000/api/contacts/:contactId */
router.delete("/:contactId", async (req, res, next) => {
  try {
    const result = await contactsServices.removeContact(req.params.contactId);
    if (!result) {
      res.status(STATUS_CODES.notFound).json({
        message: "The contact was not found.",
      });
    } else {
      res.status(STATUS_CODES.success).json({
        message: "The contact has been successfully deleted.",
      });
    }
  } catch (error) {
    respondWithError(res, error);
  }
});

/* PUT localhost:3000/api/contacts/:contactId */
router.put("/:contactId", async (req, res, next) => {
  try {
    const { error, value } = schema.validate(req.body, { abortEarly: false });
    if (error) {
      let errors = error.details;

      let message = "";
      for (i = 1; i <= errors.length; i++) {
        message += errors[i - 1].message;
        if (i < errors.length) message += ", ";
      }
      res.status(STATUS_CODES.badRequest).json({
        message: message,
      });
    } else {
      const result = await contactsServices.updateContact(
        req.params.contactId,
        req.body
      );
      if (!result) {
        res.status(STATUS_CODES.notFound).json({
          message: "The contact was not found.",
        });
      } else {
        res.status(STATUS_CODES.success).json({
          message: `The contact has been successfully updated.`,
          data: result,
        });
      }
    }
  } catch (error) {
    respondWithError(res, error);
  }
});

/* PATCH /api/contacts/:contactId/favorite */
router.patch("/:contactId/favorite", async (req, res, next) => {
  if (JSON.stringify(req.body) === "{}") {
    res.status(STATUS_CODES.badRequest).json({
      data: "Missing field favorite",
    });
  } else {
    try {
      const { error, value } = favoriteSchema.validate(req.body, {
        abortEarly: false,
      });
      if (error) {
        res.status(STATUS_CODES.badRequest).json({
          message: error.message,
        });
      } else {
        const result = await contactsServices.updateStatusContact(
          req.params.contactId,
          req.body
        );
        if (!result) {
          res.status(STATUS_CODES.notFound).json({
            message: "The contact was not found.",
          });
        } else {
          res.status(STATUS_CODES.success).json({
            message: `The contact has been successfully patched.`,
          });
        }
      }
    } catch (error) {
      respondWithError(res, error);
    }
  }
});

/**
 * Validates Contact Fields
 */
function checkIsValidContact(contact) {
  if (!contact?.name || !contact?.email || !contact?.phone) {
    return false;
  }
  return true;
}

/**
 * Handles Error Cases
 */
function respondWithError(res, error) {
  console.error(error);
  res.status(STATUS_CODES.error).json({ message: `${error}` });
}

module.exports = router;
